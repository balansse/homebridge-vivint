/**
 * Retries the plugin's startup (login, system fetch, PubNub connect) after failures that a later
 * attempt can fix, such as a Vivint 5xx or a network error (#204).
 *
 * The first retry waits a minute: the login request itself already retries every 60 s while Vivint
 * is unreachable (VivintApi.retryDelayMs), and logging in more often risks a 24h Cloudflare block.
 */

// Delays between attempts: 1, 2 and 5 minutes, then every 5 minutes
const DEFAULT_DELAYS_MS = [60, 120, 300].map((s) => s * 1000)

class StartupCancelled extends Error {
  constructor() {
    super('Startup cancelled')
    this.name = 'StartupCancelled'
  }
}

/** Delay before the next attempt, after `failures` failed attempts (1-based). The last delay repeats. */
function retryDelay(failures, delaysMs = DEFAULT_DELAYS_MS) {
  return delaysMs[Math.min(failures, delaysMs.length) - 1]
}

/**
 * Calls `attempt(attemptNumber)` until it resolves.
 *
 * After a failure, `shouldRetry(err)` decides whether to try again. If it does, `onRetry(err, delayMs, failures)`
 * is called and the next attempt starts after `delayMs`.
 *
 * @returns {{ promise: Promise<{ result: any, attempts: number }>, cancel: () => void }}
 *   `promise` resolves with the first successful result. It rejects with the first error that is not retried,
 *   or with a StartupCancelled error after `cancel()`. `cancel()` also clears a pending retry timer, so no timer
 *   outlives Homebridge's shutdown.
 */
function startWithRetry(attempt, { shouldRetry, onRetry = () => {}, delaysMs = DEFAULT_DELAYS_MS }) {
  let cancelled = false
  let timer = null
  let wake = null

  const promise = (async () => {
    for (let attempts = 1; ; attempts++) {
      if (cancelled) throw new StartupCancelled()
      try {
        const result = await attempt(attempts)
        if (cancelled) throw new StartupCancelled()
        return { result, attempts }
      } catch (err) {
        if (cancelled) throw new StartupCancelled()
        if (!shouldRetry(err)) throw err
        const delayMs = retryDelay(attempts, delaysMs)
        onRetry(err, delayMs, attempts)
        await new Promise((resolve) => {
          wake = resolve
          timer = setTimeout(resolve, delayMs)
        })
        timer = null
        wake = null
      }
    }
  })()

  return {
    promise,
    cancel() {
      cancelled = true
      if (timer) clearTimeout(timer)
      if (wake) wake()
    },
  }
}

module.exports = { startWithRetry, retryDelay, StartupCancelled, DEFAULT_DELAYS_MS }
