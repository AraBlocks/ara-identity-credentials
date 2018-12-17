const { createHash, createVerify } = require('crypto')
const { PublicKey } = require('did-document-public-key')
const parseAsn1 = require('parse-asn1')
const elliptic = require('elliptic')
const isBuffer = require('is-buffer')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const cbor = require('cbor')
const jwa = require('jwa')
const aid = require('ara-identity')

const FIDO_U2F_USER_PRESENTED = 0x01
const FIDO_U2F_RESERVED_BYTE = Buffer.from([ 0x00 ])
const FIDO_U2F = 'fido-u2f'
const ES256 = -7

/**
 * If (buffer.length == 65 && buffer[0] == 0x04), then
 * encode rawpublic key to ASN structure, adding metadata:
 *
 *  SEQUENCE {
 *    SEQUENCE {
 *      OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
 *      OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
 *    }
 *    BITSTRING <raw public key>
 * }
 *
 * Lucrily, to do that, we just need to prefix it with constant
 * 26 bytes (metadata is constant).
 * borrowed from: https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js#L139
 */
const PUBLIC_KEY_ASN_HEADER = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex'
)

function hash(buffer) {
  return createHash('sha256').update(buffer).digest()
}

function verifySignature(signature, data, publicKey) {
  const verify = createVerify('sha256')
  verify.update(data).end()
  const hash = verify._hash.digest()
  const curve = elliptic.ec('p256')
  const pub = parseAsn1(publicKey)
  return curve.verify(hash, signature, pub.data.subjectPrivateKey.data)
}

// borrowed from https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js
function parseAttestationAuthData(authData) {
  const rpIdHash = read(32)
  const flagsBuf = read(1)
  const flags = flagsBuf[0]
  const counterBuf = read(4)
  const counter = counterBuf.readUInt32BE(0)
  const aaguid = read(16)
  const credIDLenBuf = read(2)
  const credIDLen = credIDLenBuf.readUInt16BE(0)
  const credID = read(credIDLen)
  const COSEPublicKey = read.buffer.slice()

  return {
    COSEPublicKey,
    counterBuf,
    rpIdHash,
    flagsBuf,
    counter,
    aaguid,
    credID,
    flags,
  }

  function read(size) {
    read.buffer = read.buffer || authData
    const buf = read.buffer.slice(0, size)
    read.buffer = read.buffer.slice(size)
    return buf
  }
}

// borrowed from https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js
function parseAssertionAuthData(authData) {
  const rpIdHash = read(32)
  const flagsBuf = read(1)
  const flags = flagsBuf[0]
  const counterBuf = read(4)
  const counter = counterBuf.readUInt32BE(0)

  return {
    counterBuf,
    flagsBuf,
    rpIdHash,
    counter,
    flags,
  }

  function read(size) {
    read.buffer = read.buffer || authData
    const buf = read.buffer.slice(0, size)
    read.buffer = read.buffer.slice(size)
    return buf
  }
}

/**
 * borrowed from: https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js
 * +------+-------+-------+---------+----------------------------------+
 * | name | key   | label | type    | description                      |
 * |      | type  |       |         |                                  |
 * +------+-------+-------+---------+----------------------------------+
 * | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
 * |      |       |       | tstr    | the COSE Curves registry         |
 * |      |       |       |         |                                  |
 * | x    | 2     | -2    | bstr    | X Coordinate                     |
 * |      |       |       |         |                                  |
 * | y    | 2     | -3    | bstr /  | Y Coordinate                     |
 * |      |       |       | bool    |                                  |
 * |      |       |       |         |                                  |
 * | d    | 2     | -4    | bstr    | Private key                      |
 * +------+-------+-------+---------+----------------------------------+
 */
function COSEECDHAtoPKCS(COSEPublicKey) {
  const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0]
  const tag = Buffer.from([0x04])
  const x = coseStruct.get(-2)
  const y = coseStruct.get(-3)
  return Buffer.concat([tag, x, y])
}

function ASN1toPEM(buffer) {
	let PEMKey = ''
	let type

	if (buffer.length == 65 && buffer[0] == 0x04) {
		type = 'PUBLIC KEY'
		buffer = Buffer.concat([ PUBLIC_KEY_ASN_HEADER, buffer ])
	} else {
		type = 'CERTIFICATE'
	}

	let b64cert = buffer.toString('base64')

	for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
		PEMKey += b64cert.substr(i * 64, 64) + '\n'
	}

	PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`

	return PEMKey
}

function createAttestationRequest(identifier, opts) {
  return {
    pubKeyCredParams: [ { type: 'public-key', alg: ES256 } ],
    attestation: 'direct',
    challenge: crypto.randomBytes(32),
    rp: { name: opts.name || opts.domain },

    user: {
      id: isBuffer(identifier) ? identifier : Buffer.from(identifier, 'hex'),
      get name() { return this.id.toString('hex') },
      get displayName() { return `did:ara:${this.name}` }
    },
  }
}

function createAttestationResponse(identifier, opts) {
  let verified = false
  const { credentials } = opts
  const attestationObject = Buffer.from(credentials.response.attestationObject)
  const { attStmt, authData, fmt } = cbor.decodeAllSync(attestationObject)[0]
  const response = { verified: false, counter: 0, format: null, id: null }

  if (FIDO_U2F === fmt) {
    response.format = FIDO_U2F
    const auth = parseAttestationAuthData(Buffer.from(authData))

    if (! (auth.flags & FIDO_U2F_USER_PRESENTED)) {
      throw new Error('User not present during authentication.')
    }

    const clientDataHash = hash(Buffer.from(credentials.response.clientDataJSON))
    const publicKey = COSEECDHAtoPKCS(auth.COSEPublicKey)
    const signatureBase = Buffer.concat([
      FIDO_U2F_RESERVED_BYTE,
      auth.rpIdHash,
      clientDataHash,
      auth.credID,
      publicKey
    ])

    const PEMCertificate = ASN1toPEM(Buffer.from(attStmt.x5c[0]))
    const signature = attStmt.sig

    verified = verifySignature(signature, signatureBase, PEMCertificate)

    response.publicKey = publicKey
    response.counter = auth.counter
    response.id = auth.credID
  }

  response.verified = verified
  response.domain = opts.domain || opts.name
  return response
}

function createAssertionRequest(identifier, opts) {
  const allowCredentials = []
  const { domain } = opts
  const challenge = crypto.randomBytes(32)

  for (const pk of opts.publicKeys) {
    const did = new DID(pk.id)

    if (`${FIDO_U2F}-${domain}` === did.fragment) {
      const buffer = Buffer.from(pk.publicKeyHex, 'hex')

      id = buffer.slice(0, 64)
      publicKey = buffer.slice(64)

      allowCredentials.push({
        id: buffer.slice(0, 64),
        type: 'public-key',
        publicKey: buffer.slice(64),
        transports: ['usb', 'nfc', 'ble'],
      })
    }
  }

  return { allowCredentials, challenge }
}

function createAssertionResponse(identifier, opts) {
  const response = { verified: false }
  const { credentials } = opts
  const { authenticatorData } =  credentials.response
  const auth = parseAssertionAuthData(Buffer.from(authenticatorData))

  if (! (auth.flags & FIDO_U2F_USER_PRESENTED)) {
    throw new Error('User not present during authentication.')
  }

  const clientDataHash = hash(Buffer.from(credentials.response.clientDataJSON))
  const signatureBase = Buffer.concat([
    auth.rpIdHash,
    auth.flagsBuf,
    auth.counterBuf,
    clientDataHash
  ])

  const publicKey = ASN1toPEM(Buffer.from(opts.publicKey))
  const signature = Buffer.from(credentials.response.signature)

  response.verified = verifySignature(signature, signatureBase, publicKey)

  return response
}

async function create(identifier, opts) {
  const ddo = await aid.resolve(identifier, opts)
  const did = new DID(ddo.id)
  const domain = opts.domain || opts.name
  const request = createAttestationRequest(did.identifier, opts)
  const credentials = await navigator.credentials.create({ publicKey: request })
  const response = createAttestationResponse(did.identifier, {
    domain, credentials
  })

  const packed = Buffer.concat([ response.id, response.publicKey ])
  const publicKey = new PublicKey({
    id: `${did.did}#${response.format}-${response.domain}`,
    type: 'ES256VerificationKey2018',
    publicKeyHex: packed.toString('hex')
  })

  return { publicKey, attestation: response }
}

async function get(identifier, opts) {
  const { domain } = opts
  const ddo = await aid.resolve(identifier, opts)
  const did = new DID(ddo.id)

  if (!ddo) {
    return null
  }

  const publicKeys = ddo.publicKey
  const request = createAssertionRequest(did.identifier, {
    publicKeys,
    domain,
  })

  if (0 === request.allowCredentials.length) {
    return null
  }

  const { id, publicKey } = request.allowCredentials[0]
  const credentials = await navigator.credentials.get({
    publicKey: request
  })

  const response = createAssertionResponse(did.identifier, {
    credentials,
    publicKey,
    request,
    domain,
  })

  return { id, publicKey, assertion: response }
}

module.exports = {
  create,
  get,
}
