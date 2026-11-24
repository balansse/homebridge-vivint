/**
 * Coalesces rapid calls to an async function (e.g. HomeKit slider drags).
 *
 * - The first call runs immediately (leading edge).
 * - Calls made while a run is in progress (or within `waitMs` after it finished) are merged:
 *   only the most recent arguments are sent, once, after the current run completes.
 * - Every caller gets a promise that settles with the outcome of the run that carried its
 *   value or a newer one, so every HomeKit callback is answered exactly once.
 *
 * @param {(...args: any[]) => Promise<any>} fn
 * @param {number} waitMs minimum gap between the end of one run and the start of the next
 */
function coalesce(fn, waitMs = 0) {
  let running = false
  let lastRunEnd = 0
  let pending = null // { args, waiters: [{resolve, reject}] }

  async function runLoop(args, waiters) {
    running = true
    let current = { args, waiters }
    while (current) {
      try {
        const result = await fn(...current.args)
        current.waiters.forEach((w) => w.resolve(result))
      } catch (err) {
        current.waiters.forEach((w) => w.reject(err))
      }
      lastRunEnd = Date.now()
      current = pending
      pending = null
      if (current && waitMs > 0) await new Promise((r) => setTimeout(r, waitMs))
      // Pick up anything that arrived while waiting
      if (current && pending) {
        current = { args: pending.args, waiters: current.waiters.concat(pending.waiters) }
        pending = null
      }
    }
    running = false
  }

  return function coalesced(...args) {
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject }
      if (running) {
        pending = pending
          ? { args, waiters: pending.waiters.concat(waiter) }
          : { args, waiters: [waiter] }
        return
      }
      const sinceLast = Date.now() - lastRunEnd
      if (waitMs > 0 && lastRunEnd && sinceLast < waitMs) {
        // Too soon after the previous run: schedule as a trailing call
        running = true
        pending = { args, waiters: [waiter] }
        setTimeout(() => {
          const next = pending
          pending = null
          runLoop(next.args, next.waiters)
        }, waitMs - sinceLast)
        return
      }
      runLoop(args, [waiter])
    })
  }
}

module.exports = coalesce
