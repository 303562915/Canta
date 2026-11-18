// End-to-end check of the plans backend against a real PostgreSQL (WASM build).
//
// Covers what the app now does: uploading a plan owned by a device, uploading a test plan without
// a reboot proof, seeing the owner/test columns come back, and deleting a plan only as its owner.
import { PGlite } from '@electric-sql/pglite'
import { readFileSync } from 'node:fs'

const db = await new PGlite()
await db.exec(`do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;`)

const root = process.env.MIGRATIONS_DIR ?? new URL('../supabase/migrations/', import.meta.url).pathname
for (const f of ['20261116120000_telemetry_core.sql', '20261116120100_telemetry_rpc.sql', '20261118120000_plans.sql', '20261118160000_plan_test_and_owner.sql']) {
  await db.exec(readFileSync(root + f, 'utf8'))
  console.log('applied', f)
}

let failures = 0
const check = (name, condition, detail = '') => {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
  if (!condition) failures++
}

const device = { brand: 'Xiaomi', model: '23127PN0CC', codename: 'fuxi', rom: 'hyperos', rom_version: 2, sdk: 35 }

const submit = async (over = {}) => {
  const plan = {
    ...device,
    title: 'plan',
    note: '',
    packages: ['com.example.a', 'com.example.b'],
    reboot_verified: true,
    rebooted_at: '2026-11-18T06:00:00Z',
    reporter: 'dev-aaaa',
    owner: 'dev-aaaa',
    test: false,
    ...over,
  }
  try {
    const { rows } = await db.query(`select public.plan_submit($1::jsonb) as id`, [JSON.stringify(plan)])
    return { ok: true, id: rows[0].id }
  } catch (e) {
    return { ok: false, error: e.message.replace(/\n.*/s, '').slice(0, 90) }
  }
}

const list = async (over = {}) => {
  const p = { ...device, ...over }
  const { rows } = await db.query(
    `select * from public.plans_for($1, $2, $3, $4::int)`,
    [p.model, p.codename, p.rom, p.rom_version],
  )
  return rows
}

// 1. a normal verified plan comes back with its owner and a false test flag
const mine = await submit({ title: 'mine' })
check('submit verified plan', mine.ok && mine.id > 0, JSON.stringify(mine))
let rows = await list()
check('verified plan is listed', rows.length === 1, `${rows.length} rows`)
check('owner round-trips', rows[0]?.owner === 'dev-aaaa', rows[0]?.owner)
check('is_test is false', rows[0]?.is_test === false, String(rows[0]?.is_test))

// 2. a test upload is accepted and flagged, and sorts after the real plan
const test = await submit({ title: 'test plan', owner: 'dev-bbbb', reporter: 'dev-bbbb', test: true, packages: ['com.example.c'] })
check('submit test plan', test.ok && test.id > 0, JSON.stringify(test))
await db.query(`select public.plan_vote($1, 'dev-cccc')`, [test.id])
await db.query(`select public.plan_vote($1, 'dev-dddd')`, [test.id])
rows = await list()
check('test plan listed', rows.length === 2, `${rows.length} rows`)
check('test plan keeps its flag', rows.find((r) => r.id === test.id)?.is_test === true)
check(
  'real plans sort before test plans even with fewer votes',
  rows[0].id === mine.id,
  `first=${rows[0].title} votes=${rows[0].votes}`,
)

// 3. an upload without a reboot proof is still refused
const unverified = await submit({ reboot_verified: false })
check('unverified upload refused', !unverified.ok, unverified.error)
const noTime = await submit({ rebooted_at: null })
check('upload without reboot time refused', !noTime.ok, noTime.error)

// 4. owner mismatch deletes nothing
let del = await db.query(`select public.plan_delete($1, 'dev-zzzz') as ok`, [mine.id])
check('foreign owner cannot delete', del.rows[0].ok === false, String(del.rows[0].ok))
let empty = await db.query(`select public.plan_delete($1, '') as ok`, [mine.id])
check('empty owner cannot delete', empty.rows[0].ok === false, String(empty.rows[0].ok))
rows = await list()
check('plan survived the refused deletions', rows.some((r) => r.id === mine.id))

// 5. the owner can delete, and votes/comments go with it
await db.query(`select public.plan_comment($1, 'nice', 'dev-cccc')`, [test.id])
del = await db.query(`select public.plan_delete($1, 'dev-bbbb') as ok`, [test.id])
check('owner deletes own plan', del.rows[0].ok === true, String(del.rows[0].ok))
rows = await list()
check('deleted plan is gone from the list', !rows.some((r) => r.id === test.id), `${rows.length} rows`)
const votes = await db.query(`select count(*)::int as n from plan_votes where plan_id = $1`, [test.id])
const comments = await db.query(`select count(*)::int as n from plan_comments where plan_id = $1`, [test.id])
check('votes cascaded', votes.rows[0].n === 0, String(votes.rows[0].n))
check('comments cascaded', comments.rows[0].n === 0, String(comments.rows[0].n))

// 6. deleting twice is a no-op, not an error
del = await db.query(`select public.plan_delete($1, 'dev-bbbb') as ok`, [test.id])
check('second delete returns false', del.rows[0].ok === false, String(del.rows[0].ok))

// 7. another device/ROM version still sees nothing
check('other model sees nothing', (await list({ model: 'Other' })).length === 0)
check('other ROM version sees nothing', (await list({ rom_version: 1 })).length === 0)

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILED`)
process.exit(failures === 0 ? 0 : 1)
