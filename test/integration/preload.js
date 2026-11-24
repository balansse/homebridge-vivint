// Loaded into the Homebridge child process via NODE_OPTIONS=--require.
// Redirects TLS connections for Vivint / PubNub hosts to the local mock server
// (certificate is trusted via NODE_EXTRA_CA_CERTS). Any other outbound TLS host is
// logged so unexpected network access shows up in test output.

const tls = require('tls')

const MOCK_PORT = Number(process.env.VIVINT_MOCK_PORT)
const REDIRECT = /(^|\.)vivintsky\.com$|(^|\.)pndsn\.com$|(^|\.)pubnub\.com$/

const originalConnect = tls.connect

tls.connect = function patchedConnect(...args) {
  let options
  if (typeof args[0] === 'object' && args[0] !== null) {
    options = { ...args[0] }
    args[0] = options
  } else if (typeof args[0] === 'number' || typeof args[0] === 'string') {
    // (port[, host][, options][, callback])
    const port = args.shift()
    const host = typeof args[0] === 'string' ? args.shift() : undefined
    const opts = typeof args[0] === 'object' && args[0] !== null ? args.shift() : {}
    options = { ...opts, port, host: host || opts.host }
    args.unshift(options)
  } else {
    return originalConnect.apply(this, args)
  }

  const target = options.servername || options.host || options.hostname
  if (target && REDIRECT.test(target)) {
    options.servername = target
    options.host = '127.0.0.1'
    options.hostname = '127.0.0.1'
    options.port = MOCK_PORT
  } else if (target && target !== '127.0.0.1' && target !== 'localhost') {
    process.stderr.write(`[integration-preload] unexpected outbound TLS connection to ${target}\n`)
  }
  return originalConnect.apply(this, args)
}
