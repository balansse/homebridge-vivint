const assert = require('assert')
const coalesce = require('../lib/coalesce.js')

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

describe('coalesce', function () {
  it('runs the first call immediately', async function () {
    const calls = []
    const fn = coalesce(async (v) => { calls.push(v); return v * 2 }, 50)
    assert.strictEqual(await fn(1), 2)
    assert.deepStrictEqual(calls, [1])
  })

  it('merges calls made while running into one trailing call with the latest value', async function () {
    const calls = []
    const fn = coalesce(async (v) => { calls.push(v); await sleep(30); return v }, 20)
    const results = await Promise.all([fn(1), fn(2), fn(3), fn(4)])
    assert.deepStrictEqual(calls, [1, 4])
    assert.deepStrictEqual(results, [1, 4, 4, 4])
  })

  it('delays a call made within waitMs of the previous run', async function () {
    const calls = []
    const fn = coalesce(async (v) => { calls.push([v, Date.now()]); return v }, 60)
    await fn(1)
    const t0 = Date.now()
    await fn(2)
    assert.ok(Date.now() - t0 >= 50, 'second call waited')
    assert.deepStrictEqual(calls.map((c) => c[0]), [1, 2])
  })

  it('rejects every waiter of a failing run, then recovers', async function () {
    let fail = true
    const fn = coalesce(async (v) => { await sleep(10); if (fail) throw new Error(`boom ${v}`); return v }, 0)
    const p1 = fn(1)
    const p2 = fn(2)
    const p3 = fn(3)
    await assert.rejects(p1, /boom 1/)
    await assert.rejects(p2, /boom 3/)
    await assert.rejects(p3, /boom 3/)
    fail = false
    assert.strictEqual(await fn(5), 5)
  })

  it('answers every caller exactly once', async function () {
    let settled = 0
    const fn = coalesce(async (v) => { await sleep(5); return v }, 10)
    await Promise.all(Array.from({ length: 20 }, (_, i) => fn(i).then(() => settled++)))
    assert.strictEqual(settled, 20)
  })
})
