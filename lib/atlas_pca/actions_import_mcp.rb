# frozen_string_literal: true

# MCP `tools/list` to drafts (native port of the MCP importer of the TypeScript reference @atlasauth/pca-actions). The annotations are
# HINTS from the tool's own server and are untrusted: they can only add restriction (destructive, network egress); every output is
# `unreviewed`.
require_relative 'actions_import_common'

module AtlasPca
  module ActionsImportMcp
    C = AtlasPca::ActionsImportCommon
    J = C::J
    UNDEF = C::UNDEF

    module_function

    # `source` is a `tools/list` result {"tools": [...]} or the tool array itself.
    def import_mcp(source, opts = nil)
      c = C.new_ctx('mcp', source, opts)
      tools = if source.is_a?(Array) then source
              elsif source.is_a?(Hash) && source['tools'].is_a?(Array) then source['tools']
              end
      raise C::Err.new('bad_source', 'an MCP source is a tool array or a tools/list result {tools: [...]}') if tools.nil?

      seen = {}
      tools.each do |t|
        if !t.is_a?(Hash) || !t['name'].is_a?(String) || J.u16len(t['name']).zero? || J.u16len(t['name']) > 256
          C.add_todo(c, '(tool)', 'skipped_op', 'an entry without a usable name is skipped')
          next
        end
        name = t['name']
        if seen.key?(name.b)
          C.add_todo(c, name, 'duplicate_tool', 'a tool name listed twice; the first is kept')
          next
        end
        seen[name.b] = true
        c.root = t['inputSchema']
        bud = C.new_budget(c)
        inp = C.resolve_schema(t['inputSchema'], c, bud, "#{name}: inputSchema")
        params = {}
        C.flatten_object(inp, c, bud, name, params)
        a = t['annotations'].is_a?(Hash) ? t['annotations'] : {}
        read = a['readOnlyHint'] == true && a['destructiveHint'] != true
        effects = if read then ['read']
                  elsif a['destructiveHint'] == true then %w[update delete]
                  else ['update']
                  end
        C.emit_def(
          c, name, effects, 'one', params, { 'mcp' => { 'tool' => C.clip(name, 256) } },
          title: a['title'].is_a?(String) && !a['title'].empty? ? a['title'] : t.fetch('title', UNDEF),
          description: t['description'],
          idempotency: a['idempotentHint'] == true ? { 'mode' => 'natural' } : nil,
          traits: a['openWorldHint'] == true ? C.with_trait(nil, 'pca.network_egress') : nil
        )
      end
      C.finish(c)
    end
  end
end
