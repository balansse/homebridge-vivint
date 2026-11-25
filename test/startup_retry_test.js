const assert = require('assert')
const { startWithRetry, retryDelay, StartupCancelled, DEFAULT_DELAYS_MS } = require('../lib/startup_retry.js')

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

describe('startWithRetry (#204)', function () {
  it('waits 1, 2 and 5 minutes, then every 5 minutes', function () {
    assert.deepStrictEqual(DEFAULT_DELAYS_MS, [60000, 120000, 300000])
    assert.deepStrictEqual([1, 2, 3, 4, 10].map((n) => retryDelay(n)), [60000, 120000, 300000, 300000, 300000])
    // Never faster than the login request's own retry (VivintApi.retryDelayMs): Cloudflare blocks fast logins
    assert.ok(DEFAULT_DELAYS_MS.every((ms) => ms >= 60000))
  })

  it('resolves with the first result without retrying', async function () {
    let calls = 0
    const { promise } = startWithRetry(async () => { calls++; return 'ok' }, { shouldRetry: () => true })
    assert.deepStrictEqual(await promise, { result: 'ok', attempts: 1 })
    assert.strictEqual(calls, 1)
  })

  it('retries with backoff until an attempt succeeds', async function () {
    const attempts = []
    const retries = []
    const { promise } = startWithRetry(async (n) => {
      attempts.push(n)
      if (n < 4) throw new Error(`HTTP 500 #${n}`)
      return 'connected'
    }, {
      shouldRetry: () => true,
      onRetry: (err, delayMs, failures) => retries.push([err.message, delayMs, failures]),
      delaysMs: [5, 10, 20],
    })
    assert.deepStrictEqual(await promise, { result: 'connected', attempts: 4 })
    assert.deepStrictEqual(attempts, [1, 2, 3, 4])
    assert.deepStrictEqual(retries, [['HTTP 500 #1', 5, 1], ['HTTP 500 #2', 10, 2], ['HTTP 500 #3', 20, 3]])
  })

  it('repeats the last delay', async function () {
    const delays = []
    const { promise } = startWithRetry(async (n) => {
      if (n < 5) throw new Error('down')
      return n
    }, { shouldRetry: () => true, onRetry: (err, delayMs) => delays.push(delayMs), delaysMs: [1, 3] })
    await promise
    assert.deepStrictEqual(delays, [1, 3, 3, 3])
  })

  it('stops at an error that is not retried', async function () {
    class AuthError extends Error {}
    let calls = 0
    const retries = []
    const { promise } = startWithRetry(async (n) => {
      calls++
      throw n === 1 ? new Error('HTTP 500') : new AuthError('HTTP 401')
    }, {
      shouldRetry: (err) => !(err instanceof AuthError),
      onRetry: (err) => retries.push(err.message),
      delaysMs: [1],
    })
    await assert.rejects(promise, AuthError)
    assert.strictEqual(calls, 2)
    assert.deepStrictEqual(retries, ['HTTP 500'])
  })

  it('cancel() during the wait clears the timer and makes no further attempt', async function () {
    let calls = 0
    const retry = startWithRetry(async () => { calls++; throw new Error('HTTP 500') }, {
      shouldRetry: () => true, delaysMs: [60000],
    })
    await sleep(20)
    const t0 = Date.now()
    retry.cancel()
    await assert.rejects(retry.promise, StartupCancelled)
    assert.ok(Date.now() - t0 < 1000, 'settles right away instead of after the delay')
    await sleep(20)
    assert.strictEqual(calls, 1)
  })

  it('cancel() during an attempt discards its result and does not retry', async function () {
    let calls = 0
    let release
    const retry = startWithRetry(() => {
      calls++
      return new Promise((resolve) => { release = resolve })
    }, { shouldRetry: () => true, delaysMs: [1] })
    await sleep(5)
    retry.cancel()
    release('late')
    await assert.rejects(retry.promise, StartupCancelled)
    assert.strictEqual(calls, 1)
  })
})
