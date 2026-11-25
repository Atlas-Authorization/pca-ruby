# frozen_string_literal: true

# Replays the TS-reference oracle of the compliance evidence module (test-data/ref-compliance.json.gz): AuditEvent normalisation,
# the control-mapping table, per-framework compliance reports, their JSON and Markdown renderers and the console-activity framework
# report. Results compare as canonical JSON (own serializer: a report may carry a lone surrogate, which JSON.generate refuses).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/compliance'
require 'minitest/autorun'

class TestRefCompliance < Minitest::Test
  C = AtlasPca::Compliance
  BY_FN = Ref.load('compliance')

  # {"$num": "NaN" | "Infinity" | "-Infinity"} -> the Float
  def self.num(v)
    case v
    when Hash
      return { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.fetch(v['$num']) if v.size == 1 && v.key?('$num')

      v.transform_values { |x| num(x) }
    when Array then v.map { |x| num(x) }
    else v
    end
  end

  def self.call(name) = ->(*a) { C.public_send(name, *num(a)) }

  MAP = {
    'constants' => -> { { 'COMPLIANCE_FRAMEWORKS' => C::COMPLIANCE_FRAMEWORKS, 'CONTROL_MAPPINGS' => C::CONTROL_MAPPINGS } },
    'controlMappings' => call(:control_mappings),
    'toAuditEvent' => call(:to_audit_event),
    'toComplianceReport' => call(:to_compliance_report),
    'renderJson' => call(:render_json),
    'renderMarkdown' => call(:render_markdown),
    'frameworkReport' => call(:framework_report),
    'frameworkReportToMarkdown' => call(:framework_report_to_markdown)
  }.freeze

  SAME = ->(got, out, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(got))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(out))) }

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn], compare: SAME) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 812, BY_FN.values.sum(&:length), 'compliance'
  end

end
