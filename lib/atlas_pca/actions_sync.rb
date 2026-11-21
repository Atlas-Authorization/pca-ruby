# frozen_string_literal: true

# Keep a platform's action definitions in step with the sources they were imported from (native port of sync.ts of the TypeScript
# reference @atlasauth/pca-actions). Pure: the caller fetches the source and stores the lock. A def the lock does not attribute to this
# source is never touched; a changed operation is never carried over as confirmed.
require_relative 'actions'
require_relative 'actions_diff'

module AtlasPca
  module ActionsSync
    A = AtlasPca::Actions

    module_function

    def as_imported(d) = d['review']['state'] == 'confirmed' ? d.merge('review' => { 'state' => 'unreviewed' }) : d

    # Merge a fresh import of one source into the current defs: {defs, entries, deprecated, lock, needsReview}.
    def sync_source(current, imported, spec_digest, now, lock = nil, registry = nil, verifier = nil)
      reg = registry || A::CORE_REGISTRY
      cur = current.to_h { |d| [d['verb'], d] }
      imp = imported.to_h { |d| [d['verb'], as_imported(d)] }
      locked_ops = (lock || {})['ops'] || {}
      ops = {}
      entries = []
      defs = []
      imp.keys.sort_by { |v| A.u16key(v) }.each do |verb|
        d = imp[verb]
        dg = A.def_digest(d)
        ops[verb] = dg
        old = cur[verb]
        locked = lock.nil? ? nil : locked_ops[verb]
        if old.nil?
          entries << { 'verb' => verb, 'change' => 'added' }
          defs << d
        elsif locked == dg || (locked.nil? && A.def_digest(old) == dg)
          entries << { 'verb' => verb, 'change' => 'unchanged' }
          defs << old
        else
          diff = begin
            ActionsDiff.diff_defs(old, d, reg, verifier)
          rescue StandardError => e
            { 'class' => 'incomparable', 'reasons' => [e.message] }
          end
          entries << { 'verb' => verb, 'change' => 'changed', 'diff' => diff }
          defs << d
        end
      end
      deprecated = locked_ops.keys.reject { |v| imp.key?(v) }.sort_by { |v| A.u16key(v) }
      deprecated.each { |v| entries << { 'verb' => v, 'change' => 'removed' } }
      { 'defs' => defs, 'entries' => entries, 'deprecated' => deprecated, 'lock' => { 'spec_digest' => spec_digest, 'ops' => ops, 'synced_at' => now },
        'needsReview' => entries.any? { |e| %w[added changed].include?(e['change']) } }
    end

    # One line per changed entry, then a summary.
    def sync_text(r)
      lines = []
      r['entries'].each do |e|
        next if e['change'] == 'unchanged'

        diff = e['diff']
        extra = ''
        extra = "  (#{diff['class']}#{diff['reasons'].empty? ? '' : ": #{diff['reasons'].join(', ')}"})" if diff
        lines << "#{e['change'].ljust(9)} #{e['verb']}#{extra}"
      end
      n = ->(c) { r['entries'].count { |e| e['change'] == c } }
      lines << "#{n.call('added')} added, #{n.call('changed')} changed, #{n.call('removed')} removed (deprecated), #{n.call('unchanged')} unchanged" \
               "#{r['needsReview'] ? '; added and changed actions are unreviewed (strict) until a reviewer confirms them' : ''}"
      lines.join("\n")
    end
  end
end
