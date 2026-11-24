// Minimal HTTPS client for the Vivint API, replacing the deprecated `request` package.
//
// It deliberately reproduces request's wire format (only Cookie / Cache-Control / Host /
// Connection / Content-Length, no User-Agent, Accept or Content-Type headers) because the
// Vivint API sits behind Cloudflare and header changes can trigger bot protection.
//
// Errors never carry request headers or bodies, so logging them cannot leak the session cookie.

const https = require('https')

const agent = new https.Agent({ keepAlive: true })
const DEFAULT_TIMEOUT_MS = 30 * 1000
const MAX_REDIRECTS = 5

class VivintApiError extends Error {
  constructor(message, { status, method, path, code } = {}) {
    super(message)
    this.name = 'VivintApiError'
    this.status = status
    this.method = method
    this.path = path
    this.code = code
  }
}

/**
 * @param {object} opts
 * @param {string} opts.url
 * @param {string} [opts.method=GET]
 * @param {object} [opts.headers]
 * @param {string|Buffer|object} [opts.body] objects are JSON-encoded (and sent with
 *        Content-Type: application/json, like request's `json: true`)
 * @param {boolean} [opts.throwOnError=true] reject on non-2xx responses
 * @returns {Promise<{status:number, headers:object, body:string, json:function}>}
 */
function httpRequest(opts, redirects = 0) {
  const method = (opts.method || 'GET').toUpperCase()
  const url = new URL(opts.url)
  const headers = { ...(opts.headers || {}) }

  let body
  if (opts.body !== undefined && opts.body !== null) {
    if (Buffer.isBuffer(opts.body) || typeof opts.body === 'string') {
      body = Buffer.from(opts.body)
    } else {
      body = Buffer.from(JSON.stringify(opts.body))
      if (!Object.keys(headers).some((h) => h.toLowerCase() === 'content-type')) headers['content-type'] = 'application/json'
    }
    headers['content-length'] = body.length
  }

  const describe = `${method} ${url.pathname}`

  return new Promise((resolve, reject) => {
    const req = https.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || undefined,
      path: url.pathname + url.search,
      method,
      headers,
      agent: opts.agent || agent,
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('error', (err) => reject(new VivintApiError(`${describe} failed: ${err.code || err.message}`, { method, path: url.pathname, code: err.code })))
      res.on('end', () => {
        const status = res.statusCode
        // Follow redirects for GET only (same behaviour as request's default followRedirect)
        if (method === 'GET' && status >= 300 && status < 400 && res.headers.location && redirects < MAX_REDIRECTS) {
          return resolve(httpRequest({ ...opts, url: new URL(res.headers.location, url).toString() }, redirects + 1))
        }
        const text = Buffer.concat(chunks).toString('utf8')
        const response = {
          status,
          headers: res.headers,
          body: text,
          json() {
            return text.length ? JSON.parse(text) : undefined
          },
        }
        if (opts.throwOnError !== false && (status < 200 || status >= 300)) {
          return reject(new VivintApiError(`${describe} failed: HTTP ${status}`, { status, method, path: url.pathname }))
        }
        resolve(response)
      })
    })
    req.setTimeout(opts.timeoutMs || DEFAULT_TIMEOUT_MS, () => {
      req.destroy(Object.assign(new Error('request timed out'), { code: 'ETIMEDOUT' }))
    })
    req.on('error', (err) => reject(new VivintApiError(`${describe} failed: ${err.code || err.message}`, { method, path: url.pathname, code: err.code })))
    if (body) req.write(body)
    req.end()
  })
}

/** Returns the `s=...` session cookie from a response's Set-Cookie headers, if present. */
function sessionCookie(response) {
  const setCookies = response.headers['set-cookie']
  if (!Array.isArray(setCookies)) return undefined
  const cookie = setCookies.find((c) => typeof c === 'string' && c.startsWith('s='))
  return cookie ? cookie.split(';')[0] : undefined
}

/** A safe, single-line description of any error for logging (never includes headers/cookies). */
function describeError(err) {
  if (!err) return 'unknown error'
  if (err instanceof VivintApiError) return err.message
  if (err instanceof Error) return err.message
  return String(err)
}

module.exports = { httpRequest, sessionCookie, describeError, VivintApiError }
