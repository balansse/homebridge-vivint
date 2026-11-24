// Keeps the PubNub real-time stream alive.
//
// PubNub v14 retries a failed subscribe request a few times on its own (exponential, ~2 minutes in total)
// and then gives up: the event engine parks in a "failed" state and emits one status event
// (PNDisconnectedUnexpectedlyCategory or PNConnectionErrorCategory). Nothing reconnects after that, so
// momentary events (motion, doorbell, camera) stop until Homebridge restarts. Non-retriable errors such
// as HTTP 403 give up immediately.
//
// This supervisor:
// - calls pubnub.reconnect() with exponential backoff after a failure status, until the connection is back;
// - on check() (called periodically), unsubscribes and resubscribes when nothing has been heard from
//   PubNub for `staleMs`, in case the client got stuck without reporting it;
// - logs one line per state change (lost / restored), everything else at debug level.

const FAILURE_CATEGORIES = new Set([
  'PNDisconnectedUnexpectedlyCategory',
  'PNConnectionErrorCategory',
  'PNNetworkDownCategory',
  'PNNetworkIssuesCategory',
  'PNTimeoutCategory',
  'PNAccessDeniedCategory',
  'PNBadRequestCategory',
  'PNUnknownCategory',
])

const CONNECTED_CATEGORIES = new Set(['PNConnectedCategory', 'PNReconnectedCategory'])

class PubNubSupervisor {
  /**
   * @param {object} pubnub - PubNub client (reconnect, subscribe, unsubscribeAll).
   * @param {string[]} channels - Channels to (re)subscribe to.
   * @param {object} log - Homebridge logger.
   * @param {object} [options]
   */
  constructor(pubnub, channels, log, {
    initialDelayMs = 5000,
    maxDelayMs = 5 * 60 * 1000,
    staleMs = 60 * 60 * 1000,
    now = Date.now,
    setTimer = setTimeout,
    clearTimer = clearTimeout,
  } = {}) {
    this.pubnub = pubnub
    this.channels = channels
    this.log = log
    this.initialDelayMs = initialDelayMs
    this.maxDelayMs = maxDelayMs
    this.staleMs = staleMs
    this.now = now
    this.setTimer = setTimer
    this.clearTimer = clearTimer

    this.state = 'connecting' // 'connecting' | 'up' | 'down'
    this.attempts = 0
    this.reconnectTimer = null
    this.lastActivity = now()
    this.destroyed = false
  }

  /** Feed every PubNub status event here. */
  handleStatus(statusEvent) {
    if (this.destroyed || !statusEvent) return
    const category = statusEvent.category

    if (CONNECTED_CATEGORIES.has(category)) {
      this.lastActivity = this.now()
      this.cancelReconnect()
      if (this.state === 'down') this.log.info('PubNub connection restored; real-time updates resumed')
      else this.log.debug(`Connected to PubNub (${category})`)
      this.state = 'up'
      this.attempts = 0
      return
    }

    if (FAILURE_CATEGORIES.has(category)) {
      const delay = this.nextDelay()
      const reason = statusEvent.error ? `${category}: ${statusEvent.error}` : category
      if (this.state !== 'down') {
        this.log.warn(`PubNub connection lost (${reason}); real-time updates paused, reconnecting in ${Math.round(delay / 1000)}s`)
      } else {
        this.log.debug(`PubNub reconnect failed (${reason}); next attempt in ${Math.round(delay / 1000)}s`)
      }
      this.state = 'down'
      this.scheduleReconnect(delay)
      return
    }

    this.log.debug(`PubNub status: ${category}`)
  }

  /** Call for every received message. */
  noteActivity() {
    this.lastActivity = this.now()
  }

  /** Periodic watchdog: resubscribe if nothing has been heard from PubNub for `staleMs`. */
  check() {
    if (this.destroyed) return
    const idleMs = this.now() - this.lastActivity
    if (idleMs < this.staleMs) return
    const idleMins = Math.round(idleMs / 60000)
    if (this.state === 'down') this.log.info(`PubNub still disconnected after ${idleMins} min; resubscribing`)
    else this.log.debug(`No PubNub activity for ${idleMins} min; resubscribing as a precaution`)
    this.resubscribe()
  }

  nextDelay() {
    return Math.min(this.initialDelayMs * Math.pow(2, this.attempts), this.maxDelayMs)
  }

  scheduleReconnect(delay) {
    if (this.reconnectTimer) return // one pending attempt at a time
    this.attempts += 1
    this.reconnectTimer = this.setTimer(() => {
      this.reconnectTimer = null
      if (this.destroyed) return
      try {
        this.pubnub.reconnect()
      } catch (err) {
        this.log.debug('PubNub reconnect threw:', err && err.message)
      }
    }, delay)
  }

  cancelReconnect() {
    if (this.reconnectTimer) this.clearTimer(this.reconnectTimer)
    this.reconnectTimer = null
  }

  resubscribe() {
    this.cancelReconnect()
    this.lastActivity = this.now()
    if (this.state !== 'down') this.state = 'connecting'
    try {
      this.pubnub.unsubscribeAll()
      this.pubnub.subscribe({ channels: this.channels })
    } catch (err) {
      this.log.debug('PubNub resubscribe threw:', err && err.message)
    }
  }

  destroy() {
    this.destroyed = true
    this.cancelReconnect()
  }
}

module.exports = PubNubSupervisor
module.exports.FAILURE_CATEGORIES = FAILURE_CATEGORIES
