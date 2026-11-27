# frozen_string_literal: true

# AsyncAPI 2.x / 3.x to drafts (native port of the AsyncAPI importer of the TypeScript reference @atlasauth/pca-actions). Sending to a
# channel is effect `send`, receiving is `read`; the message payload becomes the params. A broker publish leaves the trust domain, so
# it stays `send` unless the channel carries the allow-listed `x-pca-internal: true`.
require_relative 'actions_import_common'

module AtlasPca
  module ActionsImportAsyncapi
    C = AtlasPca::ActionsImportCommon
    J = C::J
    U16 = C::U16
    UNDEF = C::UNDEF

    module_function

    def deref(c, x, where, depth = 0)
      return nil unless x.is_a?(Hash)
      return x unless x['$ref'].is_a?(String)

      if depth > c.lim['max_ref_depth']
        C.add_todo(c, where, 'ref_depth', 'a reference chain is too deep')
        return nil
      end
      t = C.pointer(c.root, x['$ref'])
      if t.nil?
        C.add_todo(c, where, 'unresolved_ref', "reference '#{C.clip(x['$ref'], 120)}' does not resolve locally")
        return nil
      end
      deref(c, t, where, depth + 1)
    end

    def payload_params(c, msgs, where, params, bud)
      resolved = msgs.map { |m| deref(c, m, where) }.compact
      return if resolved.empty?

      C.add_todo(c, where, 'message_variants', "#{resolved.length} message variants: only the first is declared") if resolved.length > 1
      payload = resolved[0].fetch('payload', UNDEF)
      return if payload.equal?(UNDEF)

      s = C.resolve_schema(payload, c, bud, "#{where}: payload")
      if s['type'] == 'object' || s['properties'].is_a?(Hash)
        C.flatten_object(s, c, bud, where, params)
      else
        C.add_todo(c, where, 'payload_shape', 'the message payload is not an object schema; it is not declared')
      end
    end

    def channel_params(c, ch, where, params)
      ps = deref(c, ch['parameters'], where)
      return if ps.nil?

      J.sort_utf8(ps.keys).each do |name|
        s = C.param_seg(name)
        next if params.key?(s)

        params[s] = { 'type' => 'string', 'max_len' => 256 }
      end
    end

    def import_asyncapi(source, opts = nil)
      c = C.new_ctx('asyncapi', source, opts)
      unless source.is_a?(Hash) && source['asyncapi'].is_a?(String) && J.u8(source['asyncapi']).b.match?(/\A[23]\./n)
        raise C::Err.new('bad_source', "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')")
      end

      v3 = source['asyncapi'].start_with?('3')
      channels = source['channels'].is_a?(Hash) ? source['channels'] : {}
      ns = opts['ns']
      internal = ->(ch) { C.ext?(c, 'x-pca-internal') && ch['x-pca-internal'] == true }
      emit = lambda do |op_name, ch_name, ch, action, op, msgs|
        where = "#{action} #{C.clip(ch_name, 100)}"
        bud = C.new_budget(c)
        c.root = source
        params = {}
        channel_params(c, ch, where, params)
        payload_params(c, msgs, where, params, bud)
        effects = if action == 'receive' then ['read']
                  elsif internal.call(ch) then ['create']
                  else ['send']
                  end
        C.emit_def(
          c, op_name.nil? ? where : op_name, effects, 'one', params, { 'asyncapi' => { 'channel' => C.clip(ch_name, 250), 'op' => action } },
          verb: op_name.nil? ? C.verb_of(ns, "#{ch_name} #{action}") : nil, no_alias: op_name.nil?,
          title: op['summary'].is_a?(String) ? op['summary'] : nil, description: op['description'].is_a?(String) ? op['description'] : nil
        )
      end

      if v3
        ops = source['operations'].is_a?(Hash) ? source['operations'] : {}
        J.sort_utf8(ops.keys).each do |oid|
          op = deref(c, ops[oid], oid)
          if op.nil? || !%w[send receive].include?(op['action'])
            C.add_todo(c, oid, 'skipped_op', 'an operation without action send|receive is skipped')
            next
          end
          ch_ref = deref(c, op['channel'], oid)
          next if ch_ref.nil?

          chan = op['channel']
          ch_name = if ch_ref['address'].is_a?(String) then ch_ref['address']
                    elsif chan.is_a?(Hash) && chan['$ref'].is_a?(String) then U16.to_pua(chan['$ref']).split('/', -1).last.to_s.then { |x| U16.from_pua(x) }
                    else oid
                    end
          msgs = if op['messages'].is_a?(Array) && !op['messages'].empty? then op['messages']
                 elsif ch_ref['messages'].is_a?(Hash) then J.sort_utf8(ch_ref['messages'].keys).map { |k| ch_ref['messages'][k] }
                 else []
                 end
          emit.call(oid, ch_name, ch_ref, op['action'], op, msgs)
        end
      else
        J.sort_utf8(channels.keys).each do |ch_name|
          ch = deref(c, channels[ch_name], ch_name)
          next if ch.nil?

          [%w[publish send], %w[subscribe receive]].each do |key, action|
            op = deref(c, ch[key], ch_name)
            next if op.nil?

            m = deref(c, op['message'], ch_name)
            msgs = if !m.nil? && m['oneOf'].is_a?(Array) then m['oneOf']
                   elsif !m.nil? then [m]
                   else []
                   end
            oid = op['operationId']
            emit.call(oid.is_a?(String) && !oid.empty? ? oid : nil, ch_name, ch, action, op, msgs)
          end
        end
      end
      C.finish(c)
    end
  end
end
