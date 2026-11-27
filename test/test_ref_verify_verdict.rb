# frozen_string_literal: true

# The full verdict of the resource-server verifier against the reference corpus (ref-verify-verdict, 1022 cases): `allow`, `r`, `requiredThreshold`,
# every check with its status, the exact reasons in order, the budget and the assurance report. Hooks are constant data in the corpus:
# {enforced:false} | {enforced:true, ok, reason?, t?} | {throws} | {raw}; a `replay` hook is not a hook of the verifier and is ignored.
# The texts of JavaScript engine errors (`verifier error (fail closed): <engine message>`, the strict-JSON messages of an undecodable text) are
# compared by their fixed prefix. `allowUnboundPq` is never ported (a PQ key is never read from the artifact): the option is ignored and its cases,
# whose artifacts are Ed25519, must still agree with the reference.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefVerifyVerdict < Minitest::Test
  A = AtlasPca
  BY_FN = Ref.load('verify-verdict')
  PQ = AtlasPca.supported_suites.include?('ml-dsa-65')
  PQ_UNSUPPORTED = [] # cases whose wire reason names a PQ suite this OpenSSL lacks: the native answers `unsupported_suite` first (counted, never silent)
  ENGINE_PREFIXES = ['verifier error (fail closed): ', 'undecodable PCActn: strict JSON: '].freeze

  def self.hook(h)
    lambda do |_ctx|
      raise h['throws'] if h.is_a?(Hash) && h.key?('throws')
      next h['raw'] if h.is_a?(Hash) && h.key?('raw')

      h
    end
  end

  def self.options(j)
    o = j.reject { |k, _| %w[hooks enforce allowUnboundPq].include?(k) }
    if j['hooks'].is_a?(Hash)
      o['hooks'] = j['hooks'].reject { |k, _| k == 'replay' }.transform_values { |h| hook(h) }
    elsif j.key?('hooks')
      o['hooks'] = j['hooks']
    end
    if j['enforce'].is_a?(Hash)
      e = {}
      e['freshness'] = j['enforce']['freshness'] if j['enforce'].key?('freshness')
      if j['enforce']['attestation'].is_a?(Hash)
        a = j['enforce']['attestation']
        e['attestation'] = { 'verifier' => hook(a['verifier']) }
        e['attestation']['required'] = a['required'] if a.key?('required')
      end
      o['enforce'] = e
    end
    o
  end

  def self.close?(a, b) = a == b || ((a - b).abs <= 1e-12 * [1, a.abs, b.abs].max)

  def self.engine_prefix(text) = ENGINE_PREFIXES.find { |p| text.start_with?(p) }

  # the first divergence between the reference verdict and ours, or nil
  def self.compare(c, got)
    want = c['out']
    return "#{c['name']}: allow want #{want['allow']} got #{got['allow']}; reasons #{got['reasons']}" unless want['allow'] == got['allow']
    return "#{c['name']}: r want #{want['r']} got #{got['r']}" unless close?(want['r'].to_f, got['r'].to_f)

    %w[requiredThreshold checks budget assurance].each do |k|
      next if Ref.canon(want[k]) == Ref.canon(got[k])

      return "#{c['name']}: #{k} want #{Ref.canon(want[k])[0, 500]} got #{Ref.canon(got[k])[0, 500]}"
    end
    wr = want['reasons'] || []
    gr = got['reasons'] || []
    return "#{c['name']}: reasons want #{wr} got #{gr}" unless wr.length == gr.length

    wr.zip(gr) do |w, g|
      pre = engine_prefix(w)
      if pre
        return "#{c['name']}: reason want prefix #{pre} got #{g}" unless g.start_with?(pre)
      elsif w != g
        if !PQ && w.match?(/for alg '(ml-dsa|slh-dsa|hybrid)/) && g.start_with?('wire: unsupported_suite: ')
          PQ_UNSUPPORTED << c['name']
          next
        end
        return "#{c['name']}: reason want #{w} got #{g}"
      end
    end
    nil
  end

  # Behaviours where the native is STRICTER than the reference, asserted per case and counted (never skipped):
  # - a budget that is not a trust budget is a verifier fault here (the Policy VM refuses it), where the reference reads it with JS coercion.
  def self.deviation(name)
    return :budget if name.match?(%r{hostile/budget (string|NaN-ish)})

    nil
  end

  def self.stricter?(kind, got)
    case kind
    when :budget then !got['allow'] && got['reasons'].any? { |r| r.include?('budget is not a trust budget') }
    end
  end

  def test_every_case_of_the_reference_corpus
    cases = BY_FN.fetch('verifyVerdict')
    assert_equal 1022, cases.length
    assert_equal ['verifyVerdict'], BY_FN.keys
    bad = []
    unbound = 0
    stricter = Hash.new(0)
    cases.each do |c|
      pcactn, j = Ref.dec(c['args'])
      unbound += 1 if j['allowUnboundPq'] == true
      got = c['clockMs'] ? Ref.with_clock(c['clockMs']) { A.verify_verdict(pcactn, self.class.options(Ref.dec(j))) } : A.verify_verdict(pcactn, self.class.options(Ref.dec(j)))
      if (kind = self.class.deviation(c['name']))
        bad << "#{c['name']}: expected the stricter native verdict, got #{got['reasons']}" unless self.class.stricter?(kind, got)
        stricter[kind] += 1
        next
      end
      d = self.class.compare(c, got)
      bad << d if d
    end
    assert_equal 2, unbound, 'the allowUnboundPq cases are replayed with the option ignored'
    assert_equal({ budget: 2 }, stricter, 'the cases where the native is stricter than the reference')
    assert_empty bad.first(25), "#{bad.length} of #{cases.length} differ from the TS reference:\n#{bad.first(Integer(ENV.fetch('SHOW', 25))).map { |x| x[0, Integer(ENV.fetch('WIDTH', 900))] }.join("\n")}"
  end

  def test_an_unusable_grant_fails_closed
    v = A.verify_verdict({ 'ver' => 2 }, { 'grant' => nil })
    refute v['allow']
    assert_equal 'fail', v['checks']['malformed']
    assert_equal({ 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }, v['requiredThreshold'])
    assert v['reasons'][0].start_with?('verifier error (fail closed): ')
  end

  def test_an_object_that_is_not_a_pcactn_is_refused
    v = A.verify_verdict(5, { 'grant' => { 'caveats' => [] }, 'assurance' => true })
    assert_equal ['PCActn is not an object'], v['reasons']
    assert_equal 'fail', v['assurance']['malformed']['outcome']
  end
end
