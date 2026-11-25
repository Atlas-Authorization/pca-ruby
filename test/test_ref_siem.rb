# frozen_string_literal: true

# Replays the TS-reference oracle of the SIEM export module (test-data/ref-siem.json.gz): OCSF / CEF / ECS mapping, error
# scrubbing, the HTTP and console sinks and export_batch.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/siem'
require 'minitest/autorun'

class TestRefSiem < Minitest::Test
  S = AtlasPca::Siem
  BY_FN = Ref.load('siem')

  def self.ev(rec, fmt) = S.format_decision(rec, fmt, nil)

  def self.http(spec)
    calls = []
    mode = spec['mode']
    fetch = lambda do |url, init|
      calls << { 'url' => url, 'method' => init['method'], 'headers' => init['headers'], 'body' => init['body'] }
      if mode == 'ok' then { 'ok' => true, 'status' => 200 }
      elsif mode.start_with?('st:')
        parts = mode.split(':', -1)
        res = { 'ok' => false, 'status' => parts[1].to_i }
        res['statusText'] = parts[2..].join(':') if parts.length > 2
        res
      elsif mode.start_with?('throws:') then raise mode[7..]
      else
        init['signal'].wait(5) # hang until the sink gives up
        { 'ok' => true, 'status' => 200 }
      end
    end
    sink = S.http_sink(spec['url'], spec['format'], headers: spec['headers'], content_type: spec['contentType'], name: spec['name'],
                                                    timeout_ms: spec['timeoutMs'], fetch: fetch)
    result = sink.deliver.call(spec['events'].map { |r| ev(r, spec['format']) })
    { 'name' => sink.name, 'format' => sink.format, 'result' => result, 'request' => calls[0] }
  end

  def self.console(spec)
    lines = []
    logger = lambda do |line|
      raise spec['throws'] if spec['throws']

      lines << line
    end
    sink = S.console_sink(spec['format'], logger, spec['name'])
    result = sink.deliver.call(spec['records'].map { |r| ev(r, sink.format) })
    { 'name' => sink.name, 'format' => sink.format, 'result' => result, 'lines' => lines }
  end

  def self.export(spec)
    errors = []
    delivered = []
    mode = spec['sinkMode']
    deliver = lambda do |events|
      events.each { |e| delivered << e['line'] }
      case mode
      when 'ok' then { 'ok' => true }
      when 'fail' then { 'ok' => false, 'error' => 'collector said no token=abcdef123' }
      when 'failNoError' then { 'ok' => false }
      else raise 'deliver exploded Bearer abcdefghij'
      end
    end
    on_error = lambda do |e, ctx|
      errors << { 'message' => e.message, 'sink' => ctx['sink'], 'count' => ctx['count'] }
      raise 'cb' if mode == 'throwsOnError' || spec['onErrorThrows']
    end
    sink = S::SiemSink.new('s1', spec['format'], deliver)
    result = S.export_batch(spec['records'], sink, on_error, spec['serialize'])
    { 'result' => result, 'errors' => errors, 'delivered' => delivered }
  end

  MAP = {
    'toOcsfEvent' => ->(r, o = nil) { S.to_ocsf_event(r, o) },
    'toCef' => ->(r, o = nil) { S.to_cef(r, o) },
    'toEcs' => ->(r, o = nil) { S.to_ecs(r, o) },
    'formatDecision' => ->(r, f, o = nil) { S.format_decision(r, f, o) },
    'scrubError' => ->(m) { S.scrub_error(m) },
    'httpSinkScenario' => ->(s) { http(s) },
    'consoleSinkScenario' => ->(s) { console(s) },
    'exportScenario' => ->(s) { export(s) }
  }.freeze

  def test_every_function_is_covered
    assert_equal MAP.keys.sort, BY_FN.keys.sort
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1290, BY_FN.values.sum(&:length), 'siem'
  end

end
