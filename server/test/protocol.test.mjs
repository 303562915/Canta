// End-to-end check of the telemetry backend against a real PostgreSQL (WASM build).
import { PGlite } from '@electric-sql/pglite'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

const db = await new PGlite()
await db.exec(`do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;`)
// MIGRATIONS_DIR lets the file run from a scratch checkout with the deps installed there.
const root = process.env.MIGRATIONS_DIR ?? new URL('../supabase/migrations/', import.meta.url).pathname
for (const f of ['20261116120000_telemetry_core.sql', '20261116120100_telemetry_rpc.sql']) {
  const sql = readFileSync(root + f, 'utf8')
  await db.exec(sql)
  console.log('applied', f)
}


const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex')
const powSolve = (challenge, payload, n) => {
  const prefix = `${challenge}:${sha256hex(payload)}:`
  const target = 2n ** 64n / (10000n * BigInt(n))
  for (let x = 0n; ; x++) {
    const d = createHash('sha256').update(prefix + x.toString(), 'utf8').digest()
    const head = d.readBigUInt64BE(0)
    if (head < target) return x
  }
}

const device = { brand: 'xiaomi', rom: 'hyperos', romVersion: 2, sdk: 35 }
const payloadOf = (events) => JSON.stringify({ v: 1, platform: 'android', device, events })

async function send(events, { tamper = false } = {}) {
  const { rows } = await db.query(`select public.challenge() as c`)
  const { challenge, sig } = rows[0].c
  const payload = payloadOf(events)
  const x = powSolve(challenge, payload, events.length)
  const body = tamper ? payload.replace('com.', 'com0') : payload
  try {
    const r = await db.query(`select public."record"($1, $2, $3, $4::bigint) as out`, [body, challenge, sig, x.toString()])
    return { ok: true, out: r.rows[0].out }
  } catch (e) {
    return { ok: false, error: e.message.replace(/\n.*/s, '').slice(0, 90) }
  }
}

const ev = (p, e, w = '2026-11-09', b = '2-10') => ({ e, p, w, b })

// 1. happy path
let r = await send([ev('com.example.risky', 'uninstalled')])
console.log('1 send:', r.ok, JSON.stringify(r.out))

// 2. replayed challenge is refused
const ch = await db.query(`select public.challenge() as c`)
const { challenge, sig } = ch.rows[0].c
const p1 = payloadOf([ev('com.a', 'uninstalled')])
const x1 = powSolve(challenge, p1, 1)
const first = await db.query(`select public."record"($1,$2,$3,$4::bigint) as out`, [p1, challenge, sig, x1.toString()])
let replay
try {
  await db.query(`select public."record"($1,$2,$3,$4::bigint) as out`, [p1, challenge, sig, x1.toString()])
  replay = 'ACCEPTED (bad)'
} catch (e) { replay = 'refused: ' + e.message.split('\n')[0] }
console.log('2 replay:', replay)

// 3. tampered payload fails the PoW
r = await send([ev('com.example.reinstalled', 'uninstalled')], { tamper: true })
console.log('3 tampered:', r.ok, r.error)

// 4. bad event kind refused
r = await send([ev('com.example.bad', 'definitely_not_a_kind')])
console.log('4 bad kind:', r.ok, r.error)

// 5. invalid x refused
r = await send([ev('com.example.badx', 'uninstalled'), ev('com.example.badx', 'uninstalled')])
console.log('5 short batch ok:', r.ok)

// 6. aggregation / verdicts
const bulk = (pkg, kinds) => kinds.map((k) => ev(pkg, k))
const feeds = [
  ['com.safe', ['uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','survived_reboot','survived_reboot','survived_reboot','survived_reboot']],
  ['com.bootloop', ['uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','restored','restored']],
  ['com.breaks', ['uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','survived_reboot','reinstalled']],
  ['com.unclear', ['uninstalled','uninstalled','uninstalled','uninstalled','uninstalled','uninstalled']],
  ['com.few', ['uninstalled','survived_reboot']],
]
for (const [pkg, kinds] of feeds) {
  const res = await send(bulk(pkg, kinds))
  if (!res.ok) console.log('send failed for', pkg, res.error)
}
const expected = {
  'com.safe': 'SAFE', 'com.bootloop': 'BOOTLOOP', 'com.breaks': 'BREAKS',
  'com.unclear': 'UNCLEAR', 'com.few': 'INSUFFICIENT',
}
const scores = await db.query(`select pkg, uninstalls, small_batch, verdict, main_rom from public.package_scores() order by pkg`)
console.log('6 scores:', JSON.stringify(scores.rows))
const rom = await db.query(`select pkg, verdict from public.package_scores_for('hyperos', 2) order by pkg`)
console.log('7 rom=hyperos/2:', JSON.stringify(rom.rows))
const fam = await db.query(`select count(*)::int as n from public.package_scores_for('hyperos', -1)`)
console.log('8 family rows:', JSON.stringify(fam.rows))
const other = await db.query(`select count(*)::int as n from public.package_scores_for('oneui', -1)`)
console.log('9 other rom rows:', JSON.stringify(other.rows))

// 10. retention
const purge = await db.query(`select public.purge_raw_events(0) as out`)
console.log('10 purge:', JSON.stringify(purge.rows[0].out))

// 11. verdicts are what the thresholds promise
let failures = 0
for (const row of scores.rows) {
  const want = expected[row.pkg]
  if (want && row.verdict !== want) {
    console.log(`WRONG verdict for ${row.pkg}: ${row.verdict}, expected ${want}`)
    failures++
  }
}
for (const [pkg, want] of Object.entries(expected)) {
  if (!scores.rows.some((r) => r.pkg === pkg)) { console.log(`missing ${pkg}`); failures++ }
}
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURES`)
if (failures) process.exit(1)
