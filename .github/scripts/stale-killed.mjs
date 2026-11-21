#!/usr/bin/env node
// Ruby merge gate, dead-minion rule: a ledgered EQUIVALENT mutant that a test KILLED in this run is evidence of a nondeterministic
// killer (the equivalence proof says no test can tell it from the original), not a gap in the ledger. mutation-merge.mjs fails such
// an entry as STALE; this wraps it:
//   node stale-killed.mjs <merge.log> <reports-dir> <merge exit code>     (exit code 0: nothing to do)
// Fails (exit 1) unless the merge failed ONLY by STALE ("no survivor at this site") lines, none of its survivors was unlisted, and
// every one of those lines is a mutant in a shard's killed-equivalents-<k>.json (the killed mutants whose site the ledger names,
// written by the shard step). A stale entry whose mutant was not generated, or was generated but did not die, still fails. Each
// excused entry is a ::notice:: naming it.
//   node stale-killed.mjs --selftest        both cases on a small fixture (the merge runs it first: a control that must hold)
import fs from 'node:fs';
import path from 'node:path';

const STALE = /^STALE \(no survivor at this site; killed or changed, remove it\): (\S+?)\/(\S+?\.rb):(\d+)(?: \(#(\d+)\))?(?: in (.+?))?: (.*)$/;

export function judge(log, killed, code) {
  if (code === 0) return { ok: true, notices: [], errors: [] };
  const lines = log.split('\n').map((l) => l.replace(/^\S+Z /, '').replace(/^##\[error\]/, '')); // CI timestamps / annotations
  const stale = lines.map((l) => STALE.exec(l)).filter(Boolean);
  const tally = /unlisted survivors: (\d+); stale entries: (\d+)/.exec(log);
  const errors = [];
  // every problem the checker counted must be one of the STALE lines (an error line of another shape, e.g. 'survivor site matches 2 ledger entries', would otherwise pass)
  const fail = /FAIL: (\d+) problem\(s\); \d+ entries/.exec(log);
  if (!fail || Number(fail[1]) !== stale.length) errors.push(`checker counted ${fail ? fail[1] : 'no'} problem(s), ${stale.length} are STALE lines`);
  if (!tally) errors.push('no ledger tally in the merge log (the merge failed before the ledger check)');
  else {
    if (Number(tally[1]) !== 0) errors.push(`${tally[1]} unlisted survivor(s)`);
    if (Number(tally[2]) !== stale.length || stale.length === 0) errors.push(`${tally[2]} stale entr(ies) but ${stale.length} excusable STALE line(s)`);
  }
  const bad = lines.filter((l) => /^(STALE|AMBIGUOUS|UNLISTED|duplicate|bad |fn '|multiplicity|FAIL)/.test(l) && !STALE.test(l) && !/^FAIL: \d+ problem\(s\); \d+ entries$/.test(l));
  for (const b of bad) errors.push(b);
  const notices = [];
  for (const m of stale) {
    const [, , file, , occ, fn, tail] = m;
    // tail = '<mutant, 90 chars> | <line, 70 chars>' (either side may itself contain ' | ', so compare whole, not split)
    const hit = killed.find((k) => k.file === file && tail.trimEnd() === `${k.mutant.slice(0, 90)} | ${String(k.line).trim().slice(0, 70)}`.trimEnd() && (!occ || String(k.occurrence) === occ));
    const mutant = tail;
    if (hit) notices.push(`::notice::equivalent entry killed this run (nondeterministic killer): ${file}${fn ? ` ${fn}` : ''}: ${mutant} (${hit.status})`);
    else errors.push(`stale entry, no such mutant killed this run: ${file}${fn ? ` ${fn}` : ''}: ${mutant}`);
  }
  return { ok: errors.length === 0, notices, errors };
}

function selftest() {
  const rec = { file: 'lib/atlas_pca/x.rb', mutant: 'int+1: 1 => 2', line: 'x = 1', occurrence: 1, status: 'KILLED' };
  const one = 'STALE (no survivor at this site; killed or changed, remove it): ruby-pca/lib/atlas_pca/x.rb:9 (#1) in f: int+1: 1 => 2 | x = 1';
  const tally = (u, s) => `FAIL: ${u + s} problem(s); 5 entries\nledger entries for ruby-pca: 5; unlisted survivors: ${u}; stale entries: ${s}\n`;
  const t = (name, r, ok) => { if (r.ok !== ok) { console.error(`stale-killed selftest FAILED: ${name}: ${JSON.stringify(r)}`); process.exit(1); } return r; };
  const r1 = t('killed equivalent is a notice', judge(`${one}\n${tally(0, 1)}`, [rec], 1), true);
  if (r1.notices.length !== 1 || !r1.notices[0].startsWith('::notice::equivalent entry killed this run (nondeterministic killer)')) { console.error('selftest: no notice'); process.exit(1); }
  t('not killed (not generated / survived elsewhere) stays stale', judge(`${one}\n${tally(0, 1)}`, [], 1), false);
  t('another mutant killed does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, mutant: 'int+1: 2 => 3' }], 1), false);
  t('an unlisted survivor still fails', judge(`${one}\nUNLISTED SURVIVOR: a\n${tally(1, 1)}`, [rec], 1), false);
  t('a multiplicity mismatch still fails', judge(`${one}\nmultiplicity: 1 identical survivor(s) at this site, entry covers 2: x\n${tally(0, 1)}`, [rec], 1), false);
  t('a source-line-gone stale still fails', judge(`STALE (source line gone): ruby-pca/lib/atlas_pca/x.rb:9 in f: m | l\n${tally(0, 1)}`, [rec], 1), false);
  t('an error line of another shape still fails', judge(`${one}\nsurvivor site matches 2 ledger entries: x\nFAIL: 2 problem(s); 5 entries\nledger entries for ruby-pca: 5; unlisted survivors: 0; stale entries: 1\n`, [rec], 1), false);
  t('a mutant/line containing a pipe is matched', judge(`STALE (no survivor at this site; killed or changed, remove it): ruby-pca/lib/atlas_pca/x.rb:9 in f: op: a | b => a & b | y = a | b\n${tally(0, 1)}`, [{ ...rec, mutant: 'op: a | b => a & b', line: 'y = a | b' }], 1), true);
  t('exit 0 passes', judge('', [], 0), true);
  console.log('stale-killed selftest ok');
}

if (process.argv[2] === '--selftest') selftest();
else if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  selftest(); // the control first
  const [logFile, reports, code] = process.argv.slice(2);
  const killed = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/^killed-equivalents-\d+\.json$/.test(e.name)) killed.push(...JSON.parse(fs.readFileSync(p, 'utf8'))); } };
  if (fs.existsSync(reports)) walk(reports);
  const r = judge(fs.readFileSync(logFile, 'utf8'), killed, Number(code));
  for (const n of r.notices) console.log(n);
  for (const e of r.errors) console.log(`::error::${e}`);
  process.exit(r.ok ? 0 : 1);
}
