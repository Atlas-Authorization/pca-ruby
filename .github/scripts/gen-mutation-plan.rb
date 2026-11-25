#!/usr/bin/env ruby
# frozen_string_literal: true

# Regenerates the mutation plan of workflows/mutation.yml from lib/: PLAN_FILES, the matrix rows (every file of lib/ gets rows;
# existing rows are kept as they are) and the shard jobs (one job per 250 rows: a matrix is capped at 256 jobs, the extra jobs
# are clones of `shard`). Mutant counts come from the mutator's own --list.
#   ruby gen-mutation-plan.rb <workflow.yml> <sdk root> <mutate.rb> [--target N] [--counts FILE] [--check]
# --counts FILE: "<count> <path>" lines (skips the listing); --check: write nothing, exit 1 when the plan is not current.
# New files: one file per slice group of about N mutants (a bigger file is cut into ceil(count/N) id-modulo slices, small files
# are packed together, `of` 1); shard numbers continue after the highest one.
require 'open3'

ROWS_PER_JOB = 250
wf, root, mutate, *rest = ARGV
abort 'usage: gen-mutation-plan.rb <workflow.yml> <sdk root> <mutate.rb> [--target N] [--counts FILE] [--check]' unless mutate
opt = ->(n) { (i = rest.index("--#{n}")) && rest[i + 1] }
target = (opt.call('target') || 400).to_i
text = File.read(wf)

# the shard jobs: from `  shard:` to `  merge:`
first = text.index(/^  shard:\n/) or abort 'no shard job'
last = text.index(/^  merge:\n/) or abort 'no merge job'
block = text[first...last]
jobs = block.split(/^(?=  shard(?:-\d+)?:\n)/).reject(&:empty?)
row_re = /^          - \{ shard: (\d+), files: (?:'([^']*)'|(\S+?)), slice: (\d+), of: (\d+)(, module: [\w-]+)? \}\n/
rows = jobs.flat_map { |j| j.scan(row_re).map { |s, q, u, k, m, mod| { shard: s.to_i, files: q || u, slice: k.to_i, of: m.to_i, mod: mod.to_s } } }
template = jobs.first.sub(/^        include:\n(?:#{row_re.source.sub('\A', '')})+/, "        include:\n@@ROWS@@")
abort 'matrix not found in the shard job' unless template.include?('@@ROWS@@')

plan_m = text.match(/^  PLAN_FILES: >-\n((?:    .*\n)+)/) or abort 'no PLAN_FILES'
plan = plan_m[1].split
have = rows.flat_map { |r| r[:files].split }.uniq
Dir.chdir(root) { (Dir.glob('lib/**/*.rb').sort - plan).each { |f| plan << f } }
lib = Dir.chdir(root) { Dir.glob('lib/**/*.rb').sort }
abort "plan names a file that is gone: #{plan - lib}" unless (plan - lib).empty?
todo = lib - have

counts = {}
if (cf = opt.call('counts'))
  File.readlines(cf).each { |l| c, f = l.split; counts[f] = c.to_i }
else
  todo.each { |f| out, = Open3.capture3('ruby', File.expand_path(mutate), File.join(root, f), '--list'); counts[f] = out.lines.count }
end

next_shard = rows.map { |r| r[:shard] }.max
groups = []
todo.each do |f|
  c = counts.fetch(f)
  abort "no mutants in #{f}, which has code (does the mutator parse it? run with LANG=C.UTF-8)" if c.zero? && File.read(File.join(root, f)).match?(/^\s*def /)
  if c > target
    n = (c.to_f / target).ceil
    (1..n).each { |k| groups << { files: f, slice: k, of: n } }
  else
    g = groups.last if groups.last&.key?(:size)
    if g && g[:size] + c <= target then g[:files] += " #{f}"; g[:size] += c
    else groups << { files: f, slice: 1, of: 1, size: c } end
  end
end
groups.each { |g| rows << { shard: (next_shard += 1), files: g[:files], slice: g[:slice], of: g[:of], mod: '' } }

fmt = lambda do |r|
  f = r[:files].include?(' ') ? "'#{r[:files]}'" : r[:files]
  "          - { shard: #{r[:shard]}, files: #{f}, slice: #{r[:slice]}, of: #{r[:of]}#{r[:mod]} }\n"
end
chunks = rows.each_slice(ROWS_PER_JOB).to_a
total = rows.map { |r| r[:shard] }.max
new_jobs = chunks.each_with_index.map do |ch, i|
  j = template.sub('@@ROWS@@') { ch.map(&fmt).join }.sub(/^  shard(?:-\d+)?:\n/, i.zero? ? "  shard:\n" : "  shard-#{i + 1}:\n")
  j.sub(/(name: shard \$\{\{ matrix\.shard \}\})\/\d+/, "\\1/#{total}")
end
out = text.dup
out[first...last] = new_jobs.map { |j| "#{j.rstrip}\n" }.join("\n") + "\n"
out.sub!(/^  PLAN_FILES: >-\n(?:    .*\n)+/) { "  PLAN_FILES: >-\n" + plan.each_slice(6).map { |s| "    #{s.join(' ')}\n" }.join }
out.sub!(/^  SHARDS: '\d+'/, "  SHARDS: '#{total}'")
names = chunks.each_index.map { |i| i.zero? ? 'shard' : "shard-#{i + 1}" }
out.sub!(/^  merge:\n    needs: .*\n/) { "  merge:\n    needs: [#{names.join(', ')}]\n" }
out.sub!(/^(  reuse-record:\n    needs: \[reuse, pool, natives, ).*?(, merge\])/) { "#{$1}#{names.join(', ')}#{$2}" }
if rest.include?('--check') then exit(out == text ? 0 : 1) end
File.write(wf, out)
puts "#{rows.size} rows in #{chunks.size} job(s), #{todo.size} new file(s) in #{groups.size} new row(s), SHARDS=#{total}"
