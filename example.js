const credentials = require('./')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const aid = require('ara-identity')

const domain = window.location.hostname
const servers = [
  'http://resolver.ara.one',
  'http://identity1.cafe.network',
]

main().catch(console.error)

window.onhashchange = main

async function main() {
  const id = window.location.hash.slice(1)
  let creds = null

  if (!id) {
    alert(`Please navigate to http://${domain}/#did:ara:IDENTIFIER`)
    return
  }

  creds = await credentials.get(id, { domain, servers })

  if (null === creds) {
    alert('Unauthenticated')
    creds = await credentials.create(id, { domain, servers })
    await download(creds.publicKey, creds.attestation)
  } else {
    alert(`Welcome back: ${id}`)
  }
}

async function download(publicKey, attestation) {
  const filename = `${attestation.format}-${attestation.domain}.key`
  const a = document.createElement('a')
  a.href = `data:,${JSON.stringify(publicKey)}`
  a.download = filename
  setTimeout(() => a.click())
  return new Promise((resolve) => a.onclick = resolve)
}
