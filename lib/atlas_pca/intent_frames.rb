# frozen_string_literal: true

require_relative 'intent_omega'
require_relative 'intent_learner'
require_relative 'intent_v2'
require_relative 'predicates'

# Frame and side-effect constraints: monitored state snapshots, write sets, the frame condition over everything a verb does not write
# and the verb's postconditions (exact numeric deltas, predicate conditions over env.pre / env.post / env.effect). Native port of the
# TypeScript reference (@atlasauth/pca-intent).
module AtlasPca
  module IntentFrames
    UNDEF = V2JS::UNDEF
    FRAME_STATE_DOMAIN = 'atlas-pca/intent-frame-state/v1'
    INDEX_RE = /\A(?:0|[1-9][0-9]*)\z/

    module_function

    def utf8(s) = s.b
    def js(v) = V2JS.js_str(v)

    # Digest of a state value (site-local, never cross-language: the lenient canonical form).
    def state_digest(value) = AtlasPca.b64e(AtlasPca.sha(AtlasPca.canon_bytes({ 'd' => FRAME_STATE_DOMAIN, 'v' => value.equal?(UNDEF) ? nil : value })))

    # Snapshot already-read values.
    def snapshot_state(values, keep_values = true)
      values.to_h { |k, v| [k, keep_values ? { 'digest' => state_digest(v), 'value' => v } : { 'digest' => state_digest(v) }] }
    end

    # Read every monitored variable through its (synchronous) reader and snapshot it.
    def capture_state(readers, keep_values = true)
      values = {}
      readers.keys.sort_by { |k| utf8(k) }.each { |k| values[k] = readers[k].call }
      snapshot_state(values, keep_values)
    end

    def get(root, path)
      cur = root
      path.split('.', -1).each do |s|
        if cur.is_a?(Hash) && cur.key?(s)
          cur = cur[s]
        elsif cur.is_a?(Array) && s.match?(INDEX_RE) && s.to_i < cur.length
          cur = cur[s.to_i]
        else
          return UNDEF
        end
      end
      cur
    end

    # W(action): the declared list, or the parameter-selected list (unknown parameter value: default, else empty).
    def write_set_of(spec, action)
      writes = spec['writes']
      d = writes.is_a?(Hash) && writes.key?(action['verb']) ? writes[action['verb']] : nil
      return [] if d.nil?
      return d.dup if d.is_a?(Array)

      p = d['param']
      v = get(action['params'] || {}, p.start_with?('action.params.') ? p['action.params.'.length..] : p)
      key = v.is_a?(String) || v == true || v == false || IntentOmega.number?(v) ? js(v) : nil
      mp = d['map']
      (!key.nil? && mp.key?(key) ? mp[key] : (IntentLearner.truthy(d['default']) ? d['default'] : [])).dup
    end

    def env_reads(c, out)
      return unless c.is_a?(Hash)

      if Predicates.group?(c)
        if c.key?('all_of') && c['all_of'].is_a?(Array)
          c['all_of'].each { |x| env_reads(x, out) }
        elsif c.key?('any_of') && c['any_of'].is_a?(Array)
          c['any_of'].each { |x| env_reads(x, out) }
        elsif c.key?('not')
          env_reads(c['not'], out)
        end
        return
      end
      return unless Predicates.leaf?(c)

      out << c['field'] if c['field'].start_with?('env.')
      out << c['ref'] if c['ref'].is_a?(String) && c['ref'].start_with?('env.')
    end

    def nest(s)
      root = {}
      s.each do |k, v|
        next unless v.key?('value')

        segs = k.split('.', -1)
        cur = root
        segs[0...-1].each do |seg|
          cur[seg] = {} if !cur.key?(seg) || !cur[seg].is_a?(Hash)
          cur = cur[seg]
        end
        cur[segs[-1]] = v['value']
      end
      root
    end

    # Check one executed action: the frame condition over the monitored state outside its write set and the verb's postconditions.
    # Total: never raises. attributions = [{var, actor}] excuse a change by an actor other than `self`.
    def check_frame(spec, action, pre, post, opts = nil)
      opts ||= {}
      rep = { 'status' => 'ok', 'outOfFrame' => [], 'attributed' => [], 'postViolated' => [], 'missing' => [], 'unmonitored' => false }
      begin
        if !spec.is_a?(Hash) || !spec['state'].is_a?(Array) || !action.is_a?(Hash) || !pre.is_a?(Hash) || !post.is_a?(Hash)
          raise ArgumentError, 'spec, action, pre and post must be objects (spec.state an array)'
        end

        rep['unmonitored'] = spec['state'].empty?
        w = write_set_of(spec, action)
        spec['state'].sort_by { |v| utf8(v) }.each do |v|
          next if w.include?(v)

          a = pre[v]
          b = post[v]
          if a.nil? || b.nil?
            rep['missing'] << v
            next
          end
          next if a['digest'] == b['digest']

          other = (opts['attributions'] || []).any? { |x| x['var'] == v && x['actor'] != opts['self'] }
          rep[other ? 'attributed' : 'outOfFrame'] << v
        end
        env = { 'pre' => nest(pre), 'post' => nest(post), 'effect' => IntentLearner.truthy(opts['effect']) ? opts['effect'] : {} }
        ctx = { 'action' => { 'verb' => action['verb'], 'resource' => action['resource'], 'params' => action['params'] || {} }, 'env' => env }
        (spec['post'] || []).each do |pc|
          next if pc['verb'] != action['verb']

          pending = false
          (pc['deltas'] || []).each do |d|
            x = get(env['pre'], d['path'])
            y = get(env['post'], d['path'])
            if !IntentOmega.number?(x) || !IntentOmega.number?(y)
              rep['missing'] << "#{pc['id']}:#{d['path']}"
              pending = true
            elsif y != x + d['by']
              rep['postViolated'] << pc['id']
              pending = true
              break
            end
          end
          next if pending

          reads = []
          (pc['where'] || []).each { |c| env_reads(c, reads) }
          absent = reads.select { |r| get({ 'env' => env }, r).equal?(UNDEF) }
          unless absent.empty?
            absent.each { |r| rep['missing'] << "#{pc['id']}:#{r}" }
            next
          end
          where = pc['where']
          rep['postViolated'] << pc['id'] if IntentLearner.truthy(where) && !AtlasPca.evaluate_predicates([{ 'verb' => action['verb'], 'where' => where }], ctx)['allowed']
        end
      rescue StandardError => e
        rep['missing'] << "error: #{e.message}"
      end
      rep['missing'] = rep['missing'].uniq.sort_by { |s| utf8(s) }
      rep['postViolated'] = rep['postViolated'].uniq.sort_by { |s| utf8(s) }
      rep['status'] = if !rep['outOfFrame'].empty? || !rep['postViolated'].empty? then 'violated'
                      elsif !rep['missing'].empty? then 'pending'
                      else 'ok'
                      end
      rep
    end

    # Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell for good; `ok` and
    # `pending` change nothing (a met frame is not the principal's endorsement).
    def apply_frame_report(l, o, report)
      require_relative 'intent_mapkit'
      return {} if !report.is_a?(Hash) || report['status'] != 'violated'

      { 'signal' => 'postcondition-violation', 'divergence' => IntentMapkit.apply_divergence(l, o, 0) }
    end
  end
end
