const assert = require('assert')
const PubNubSupervisor = require('../lib/pubnub_supervisor.js')

function harness(options = {}) {
  let clock = 0
  const timers = []
  const calls = []
  const logs = []
  const log = {
    debug: (...a) => logs.push(['debug', a.join(' ')]),
    info: (...a) => logs.push(['info', a.join(' ')]),
    warn: (...a) => logs.push(['warn', a.join(' ')]),
    error: (...a) => logs.push(['error', a.join(' ')]),
  }
  const pubnub = {
    reconnect: () => calls.push('reconnect'),
    unsubscribeAll: () => calls.push('unsubscribeAll'),
    subscribe: (p) => calls.push(`subscribe:${p.channels.join(',')}`),
  }
  const supervisor = new PubNubSupervisor(pubnub, ['PlatformChannel#chan'], log, {
    now: () => clock,
    setTimer: (fn, ms) => {
      const t = { fn, at: clock + ms, ms, cleared: false }
      timers.push(t)
      return t
    },
    clearTimer: (t) => { t.cleared = true },
    ...options,
  })
  const pending = () => timers.filter((t) => !t.cleared && !t.fired)
  // Advance the fake clock, firing due timers in order
  const advance = (ms) => {
    const end = clock + ms
    for (;;) {
      const due = pending().filter((t) => t.at <= end).sort((a, b) => a.at - b.at)[0]
      if (!due) break
      clock = due.at
      due.fired = true
      due.fn()
    }
    clock = end
  }
  const visible = () => logs.filter(([level]) => level !== 'debug')
  return { supervisor, calls, logs, visible, pending, advance }
}

const status = (category, error) => ({ category, error })

describe('PubNubSupervisor', function () {
  it('reconnects with exponential backoff after PubNub gives up, until connected', function () {
    const h = harness()
    h.supervisor.handleStatus(status('PNConnectedCategory'))
    h.supervisor.handleStatus(status('PNDisconnectedUnexpectedlyCategory', 'PNNetworkIssuesCategory'))
    assert.deepStrictEqual(h.pending().map((t) => t.ms), [5000])

    h.advance(5000)
    assert.deepStrictEqual(h.calls, ['reconnect'])

    // Handshake after reconnect fails again: next delay doubles
    h.supervisor.handleStatus(status('PNConnectionErrorCategory', 'PNNetworkIssuesCategory'))
    assert.deepStrictEqual(h.pending().map((t) => t.ms), [10000])
    h.advance(10000)
    h.supervisor.handleStatus(status('PNConnectionErrorCategory'))
    assert.deepStrictEqual(h.pending().map((t) => t.ms), [20000])
    h.advance(20000)
    assert.deepStrictEqual(h.calls, ['reconnect', 'reconnect', 'reconnect'])

    h.supervisor.handleStatus(status('PNConnectedCategory'))
    assert.strictEqual(h.supervisor.state, 'up')
    assert.deepStrictEqual(h.pending(), [])

    // Backoff resets after a successful connection
    h.supervisor.handleStatus(status('PNDisconnectedUnexpectedlyCategory'))
    assert.deepStrictEqual(h.pending().map((t) => t.ms), [5000])
  })

  it('caps the backoff delay', function () {
    const h = harness({ maxDelayMs: 60000 })
    for (let i = 0; i < 10; i++) {
      h.supervisor.handleStatus(status('PNConnectionErrorCategory'))
      h.advance(h.pending()[0].ms)
    }
    h.supervisor.handleStatus(status('PNConnectionErrorCategory'))
    assert.strictEqual(h.pending()[0].ms, 60000)
  })

  it('keeps a single pending reconnect when several failures arrive together', function () {
    const h = harness()
    h.supervisor.handleStatus(status('PNNetworkIssuesCategory'))
    h.supervisor.handleStatus(status('PNDisconnectedUnexpectedlyCategory'))
    h.supervisor.handleStatus(status('PNTimeoutCategory'))
    assert.strictEqual(h.pending().length, 1)
    h.advance(60000)
    assert.deepStrictEqual(h.calls, ['reconnect'])
  })

  it('logs one warning when the connection is lost and one line when it is restored', function () {
    const h = harness()
    h.supervisor.handleStatus(status('PNConnectedCategory'))
    for (let i = 0; i < 5; i++) {
      h.supervisor.handleStatus(status('PNConnectionErrorCategory', 'PNNetworkIssuesCategory'))
      h.advance(h.pending()[0].ms)
    }
    h.supervisor.handleStatus(status('PNReconnectedCategory'))
    h.supervisor.handleStatus(status('PNSubscriptionChangedCategory'))
    const visible = h.visible()
    assert.strictEqual(visible.length, 2, JSON.stringify(visible))
    assert.strictEqual(visible[0][0], 'warn')
    assert.match(visible[0][1], /PubNub connection lost \(PNConnectionErrorCategory: PNNetworkIssuesCategory\).*reconnecting in 5s/)
    assert.strictEqual(visible[1][0], 'info')
    assert.match(visible[1][1], /PubNub connection restored/)
  })

  it('treats an intentional disconnect (unsubscribe) as neither failure nor recovery', function () {
    const h = harness()
    h.supervisor.handleStatus(status('PNConnectedCategory'))
    h.supervisor.handleStatus(status('PNDisconnectedCategory'))
    assert.strictEqual(h.supervisor.state, 'up')
    assert.deepStrictEqual(h.pending(), [])
    assert.deepStrictEqual(h.visible(), [])
  })

  describe('#check (watchdog)', function () {
    it('does nothing while messages keep arriving', function () {
      const h = harness({ staleMs: 60000 })
      h.supervisor.handleStatus(status('PNConnectedCategory'))
      for (let i = 0; i < 10; i++) {
        h.advance(30000)
        h.supervisor.noteActivity()
        h.supervisor.check()
      }
      assert.deepStrictEqual(h.calls, [])
    })

    it('resubscribes quietly after a long silence while connected', function () {
      const h = harness({ staleMs: 60000 })
      h.supervisor.handleStatus(status('PNConnectedCategory'))
      h.advance(59000)
      h.supervisor.check()
      assert.deepStrictEqual(h.calls, [])
      h.advance(1000)
      h.supervisor.check()
      assert.deepStrictEqual(h.calls, ['unsubscribeAll', 'subscribe:PlatformChannel#chan'])
      assert.deepStrictEqual(h.visible(), [], 'precautionary resubscribe is logged at debug level only')
      // Not again right away
      h.supervisor.check()
      assert.strictEqual(h.calls.length, 2)
    })

    it('resubscribes when still disconnected after a long time, replacing the pending reconnect', function () {
      const h = harness({ staleMs: 120000, initialDelayMs: 60000, maxDelayMs: 600000 })
      h.supervisor.handleStatus(status('PNConnectedCategory'))
      h.supervisor.handleStatus(status('PNDisconnectedUnexpectedlyCategory'))
      h.advance(60000) // reconnect #1 at t=60s
      h.supervisor.handleStatus(status('PNConnectionErrorCategory')) // next attempt due at t=180s
      h.advance(60000)
      h.supervisor.check() // t=120s: 2 min without a connection
      assert.deepStrictEqual(h.calls, ['reconnect', 'unsubscribeAll', 'subscribe:PlatformChannel#chan'])
      assert.deepStrictEqual(h.pending(), [], 'pending reconnect cancelled')
      assert.match(h.visible().pop()[1], /still disconnected after 2 min; resubscribing/)
      h.supervisor.handleStatus(status('PNConnectedCategory'))
      assert.match(h.visible().pop()[1], /restored/)
    })
  })

  it('stops reconnecting after destroy()', function () {
    const h = harness()
    h.supervisor.handleStatus(status('PNDisconnectedUnexpectedlyCategory'))
    h.supervisor.destroy()
    assert.deepStrictEqual(h.pending(), [])
    h.supervisor.handleStatus(status('PNDisconnectedUnexpectedlyCategory'))
    h.supervisor.check()
    h.advance(10 * 60 * 1000)
    assert.deepStrictEqual(h.calls, [])
  })

  it('survives a client that throws', function () {
    const h = harness({ staleMs: 1 })
    h.supervisor.pubnub = { reconnect() { throw new Error('x') }, unsubscribeAll() { throw new Error('y') }, subscribe() {} }
    h.supervisor.handleStatus(status('PNDisconnectedUnexpectedlyCategory'))
    assert.doesNotThrow(() => h.advance(5000))
    h.advance(10)
    assert.doesNotThrow(() => h.supervisor.check())
  })
})
