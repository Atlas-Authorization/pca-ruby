# frozen_string_literal: true

# Replays the TS-reference oracle of the OpenTelemetry module (test-data/ref-otel.json.gz): redaction, span attributes and
# instrument_guard over scripted tracers, meters and guards.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/otel'
require 'minitest/autorun'

class TestRefOtel < Minitest::Test
  O = AtlasPca::Otel
  BY_FN = Ref.load('otel')

  MODES = { 'identity' => ->(s) { s }, 'upper' => ->(s) { s.upcase }, 'brackets' => ->(s) { "<#{s}>" } }.freeze

  def self.scenario(spec)
    events = []
    tm = spec['tracerMode'] || 'ok'
    mm = spec['meterMode'] || 'ok'
    boom = ->(cond) { raise 'exporter boom' if cond }

    span = Object.new
    span.define_singleton_method(:set_attribute) do |k, v|
      events << { 'ev' => 'setAttribute', 'k' => k, 'v' => v }
      boom.call(tm == 'attrThrows')
    end
    span.define_singleton_method(:set_status) do |s|
      e = { 'ev' => 'setStatus', 'code' => s['code'] }
      e['message'] = s['message'] if s.key?('message')
      events << e
      boom.call(tm == 'statusThrows')
    end
    span.define_singleton_method(:record_exception) do |e|
      events << { 'ev' => 'recordException', 'message' => e.message, 'noStack' => e.backtrace.nil? }
      boom.call(tm == 'recordThrows')
    end
    span.define_singleton_method(:end) do
      events << { 'ev' => 'end' }
      boom.call(tm == 'endThrows')
    end

    tracer = Object.new
    tracer.define_singleton_method(:start_span) do |name|
      events << { 'ev' => 'startSpan', 'name' => name }
      boom.call(tm == 'startThrows')
      span
    end

    counter = Object.new
    counter.define_singleton_method(:add) do |v, a|
      events << { 'ev' => 'add', 'v' => v, 'a' => a }
      boom.call(mm == 'addThrows')
    end
    histogram = Object.new
    histogram.define_singleton_method(:record) do |v, a|
      events << { 'ev' => 'record', 'v' => v, 'a' => a }
      boom.call(mm == 'recordThrows')
    end
    meter = Object.new
    meter.define_singleton_method(:create_counter) do |name|
      events << { 'ev' => 'createCounter', 'name' => name }
      boom.call(mm == 'createThrows')
      counter
    end
    meter.define_singleton_method(:create_histogram) do |name|
      events << { 'ev' => 'createHistogram', 'name' => name }
      histogram
    end

    g = spec['guard']
    guard = lambda do |_req|
      raise g['throws'] if g.key?('throws')

      g['result']
    end

    begin
      wrapped = O.instrument_guard(guard, tracer: spec['tracer'] ? tracer : nil, meter: spec['meter'] ? meter : nil,
                                          span_name: spec['spanName'], redact: spec['redact'] ? MODES[spec['redact']] : nil)
    rescue StandardError => e
      return { 'wrap' => e.message, 'events' => events }
    end
    outcome = begin
      { 'result' => wrapped.call('req') }
    rescue StandardError => e
      { 'threw' => e.message }
    end
    { 'outcome' => outcome, 'events' => events }
  end

  MAP = {
    'redactSecrets' => ->(t) { O.redact_secrets(t) },
    'pcaSpanAttributes' => ->(r, mode = nil) { O.pca_span_attributes(r, mode ? MODES[mode] : nil) },
    'instrumentScenario' => ->(s) { scenario(s) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1075, BY_FN.values.sum(&:length), 'otel'
  end

end
