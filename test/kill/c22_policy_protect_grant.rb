# frozen_string_literal: true

# Kill tests for lib/atlas_pca/{policy_link,policy_classes,protect,pca_grant,runtime_claim}.rb (round 2, agent c22).
# Expected values pin the TypeScript references: packages/pca/src/{policy-link,envelope-rules,policy-classes,pca-grant,runtime-class}.ts
# and the shared vectors. Every AtlasPca constant / class is resolved at CALL time inside the test blocks.
require 'openssl'
require 'base64'

module MutationKill
  module C22Ppg
    module_function

    NAME_SRC = '^[a-z][a-z0-9_]{0,63}$'
    TSD = "atlas-pca/policy-template/v1\0".b
    TTD = "atlas-pca/template-tighten/v1\0".b
    RCD = "atlas-pca/runtime-class-claim/v1\x00".b
    KEY = OpenSSL::PKey.generate_key('ED25519')
    KEY2 = OpenSSL::PKey.generate_key('ED25519')

    def skip?(*names) = (f = ENV['MUT_FILE']) && !f.empty? && !names.include?(f)

    def eq(label, got, want)
      return true if got == want && got.class == want.class

      raise "c22 #{label}: got #{got.inspect}, want #{want.inspect}"
    end

    def copy(o) = Marshal.load(Marshal.dump(o))
    def b64u(bin) = Base64.urlsafe_encode64(bin, padding: false)
    def pub(k = KEY) = b64u(k.raw_public_key)
    def sha(s) = OpenSSL::Digest::SHA256.digest(s)
    def dig(v) = b64u(sha(AtlasPca.canon_bytes(v)))
    def sign_t(d, k = KEY, dom = TSD) = { 'def' => d, 'signer' => pub(k), 'sig' => b64u(k.sign(nil, dom + sha(dig(d)))) }
    def sign_o(o, k = KEY, dom = TTD) = { 'overlay' => o, 'signer' => pub(k), 'sig' => b64u(k.sign(nil, dom + sha(dig(o)))) }
    def fail_h(reason) = { 'ok' => false, 'reason' => reason }

    # the message of the LinkRefusal a block raises (nil when it returns)
    def refusal
      yield
      nil
    rescue AtlasPca::LinkRefusal => e
      e.message
    end

    def tdef
      { 'v' => 1, 'kind' => 'pca-policy-template', 'id' => 'tpl', 'version' => '1',
        'slots' => { 'a' => { 'type' => 'string' } },
        'body' => { 'predicates' => [{ 'verb' => 'x.y', 'resource' => { '$slot' => 'a', 'pre' => '/r/' } }] } }
    end

    def with(base = tdef)
      x = copy(base)
      yield x
      x
    end

    def many(n)
      with do |x|
        x['slots'] = (0...n).to_h { |i| ["s#{i}", { 'type' => 'string' }] }
        x['body'] = { 'predicates' => [{ 'w' => (0...n).map { |i| { '$slot' => "s#{i}" } } }] }
      end
    end

    # ------------------------------------------------------------------------------------ policy_link: definitions
    def def_error_cases
      obj = 'template must be an object'
      kv = 'template v / kind mismatch'
      idm = "template id must match #{NAME_SRC}"
      verm = 'template version must be a string of 1..64 characters'
      vals = "slot 'a'.values must be a list of strings"
      slot_c = ->(decl) { with { |x| x['slots'] = { 'a' => decl } } }
      body_c = ->(b) { with { |x| x['body'] = b } }
      ph_c = ->(ph) { with { |x| x['body'] = { 'predicates' => [ph] } } }
      ids64 = (0...64).map(&:to_s)
      [
        ['nil', nil, obj], ['array', [], obj], ['string', 'x', obj], ['ok', tdef, nil],
        ['v2', with { |x| x['v'] = 2 }, kv], ['v missing', with { |x| x.delete('v') }, kv],
        ['kind other', with { |x| x['kind'] = 'other' }, kv], ['kind missing', with { |x| x.delete('kind') }, kv],
        ['id 5', with { |x| x['id'] = 5 }, idm], ['id Bad', with { |x| x['id'] = 'Bad' }, idm], ['id empty', with { |x| x['id'] = '' }, idm],
        ['id missing', with { |x| x.delete('id') }, idm], ['id 65', with { |x| x['id'] = 'a' * 65 }, idm],
        ['id 64', with { |x| x['id'] = 'a' * 64 }, nil],
        ['version 5', with { |x| x['version'] = 5 }, verm], ['version empty', with { |x| x['version'] = '' }, verm],
        ['version 65', with { |x| x['version'] = 'x' * 65 }, verm], ['version 64', with { |x| x['version'] = 'x' * 64 }, nil],
        ['version 33 astral (66 UTF-16 units)', with { |x| x['version'] = "\u{1F600}" * 33 }, verm],
        ['version 32 astral (64 units)', with { |x| x['version'] = "\u{1F600}" * 32 }, nil],
        ['slots nil', with { |x| x['slots'] = nil }, 'slots must be an object'],
        ['slots array', with { |x| x['slots'] = [] }, 'slots must be an object'],
        ['slots string', with { |x| x['slots'] = 'x' }, 'slots must be an object'],
        ['32 slots', many(32), nil], ['33 slots', many(33), 'more than 32 slots'],
        ['slot name', with { |x| x['slots'] = { 'A' => { 'type' => 'string' } } }, "slot name 'A' must match #{NAME_SRC}"],
        ['slot string', slot_c.call('x'), "slot 'a' must be an object"], ['slot nil', slot_c.call(nil), "slot 'a' must be an object"],
        ['type float', slot_c.call({ 'type' => 'float' }), "slot 'a'.type must be string, integer or set"],
        ['type missing', slot_c.call({}), "slot 'a'.type must be string, integer or set"],
        ['set without values', slot_c.call({ 'type' => 'set' }), "set slot 'a' needs a closed values list"],
        ['set values string', slot_c.call({ 'type' => 'set', 'values' => 'x' }), "set slot 'a' needs a closed values list"],
        ['set ok', slot_c.call({ 'type' => 'set', 'values' => ['p'] }), nil],
        ['values string', slot_c.call({ 'type' => 'string', 'values' => 'x' }), vals],
        ['values 5', slot_c.call({ 'type' => 'string', 'values' => 5 }), vals],
        ['values [5]', slot_c.call({ 'type' => 'string', 'values' => [5] }), vals],
        ['values nil member', slot_c.call({ 'type' => 'string', 'values' => ['a', nil] }), vals],
        ['values 65', slot_c.call({ 'type' => 'string', 'values' => ids64 + ['64'] }), vals],
        ['values 64', slot_c.call({ 'type' => 'string', 'values' => ids64 }), nil],
        ['values empty', slot_c.call({ 'type' => 'string', 'values' => [] }), nil],
        ['set values 65', slot_c.call({ 'type' => 'set', 'values' => ids64 + ['64'] }), vals],
        ['set values 64', slot_c.call({ 'type' => 'set', 'values' => ids64 }), nil],
        ['min 1.5', slot_c.call({ 'type' => 'integer', 'min' => 1.5 }), "slot 'a'.min must be a safe integer"],
        ['min -0.0', slot_c.call({ 'type' => 'integer', 'min' => -0.0 }), "slot 'a'.min must be a safe integer"],
        ['max 2^53', slot_c.call({ 'type' => 'integer', 'max' => 2**53 }), "slot 'a'.max must be a safe integer"],
        ['max string', slot_c.call({ 'type' => 'integer', 'max' => 'x' }), "slot 'a'.max must be a safe integer"],
        ['min/max ok', slot_c.call({ 'type' => 'integer', 'min' => 1, 'max' => 5 }), nil],
        # min / max are only validated on an integer slot (policy-link.ts:119)
        ['string slot ignores min', slot_c.call({ 'type' => 'string', 'min' => 1.5 }), nil],
        ['string slot ignores max', slot_c.call({ 'type' => 'string', 'max' => 'x' }), nil],
        ['set slot ignores min', slot_c.call({ 'type' => 'set', 'values' => ['p'], 'min' => -0.0 }), nil],
        ['body nil', body_c.call(nil), 'body.predicates must be an array'], ['body array', body_c.call([]), 'body.predicates must be an array'],
        ['body string', body_c.call('x'), 'body.predicates must be an array'],
        ['body no predicates', body_c.call({}), 'body.predicates must be an array'],
        ['predicates string', body_c.call({ 'predicates' => 'x' }), 'body.predicates must be an array'],
        ['caveats string', body_c.call({ 'predicates' => [], 'caveats' => 'x' }), 'body.caveats must be an array'],
        ['caveats nil', body_c.call({ 'predicates' => [], 'caveats' => nil }), 'body.caveats must be an array'],
        ['unused slot', with { |x| x['slots']['b'] = { 'type' => 'string' } }, "slot 'b' is declared but never used"],
        ['proto', ph_c.call({ '__proto__' => 1 }), "body has the forbidden key '__proto__'"],
        ['constructor deep', ph_c.call([[{ 'k' => { 'constructor' => 1 } }]]), "body has the forbidden key 'constructor'"],
        ['prototype', ph_c.call({ 'prototype' => 1 }), "body has the forbidden key 'prototype'"],
        ['unknown member', ph_c.call({ '$slot' => 'a', 'x' => 1 }), "placeholder has unknown member 'x'"],
        ['undeclared', ph_c.call({ 'k' => { '$slot' => 'zz' } }), "placeholder names undeclared slot 'zz'"],
        ['undeclared 5', ph_c.call({ '$slot' => 5 }), "placeholder names undeclared slot '5'"],
        ['undeclared nil', ph_c.call({ '$slot' => nil }), "placeholder names undeclared slot 'null'"],
        ['pre 5', ph_c.call({ '$slot' => 'a', 'pre' => 5 }), 'placeholder pre must be a string'],
        ['post 5', ph_c.call({ '$slot' => 'a', 'post' => 5 }), 'placeholder post must be a string'],
        ['pre post ok', ph_c.call({ '$slot' => 'a', 'pre' => 'p', 'post' => 'q' }), nil]
      ].each { |label, d, want| eq("template_def_error #{label}", AtlasPca.template_def_error(d), want) }
      true
    end

    def scan_cases
      eq('scan array', AtlasPca.link_scan([1, 'x', nil], {}, []), nil)
      eq('scan hash', AtlasPca.link_scan({ 'a' => 1 }, {}, []), nil)
      eq('scan scalar', AtlasPca.link_scan(5, {}, []), nil)
      used = []
      eq('scan placeholder', AtlasPca.link_scan({ '$slot' => 'a', 'pre' => 'p', 'post' => 'q' }, { 'a' => {} }, used), nil)
      eq('scan used', used, ['a'])
      eq('scan non-string slot name is undeclared even when decl has that key',
         AtlasPca.link_scan({ '$slot' => 5 }, { 5 => {} }, []), "placeholder names undeclared slot '5'")
      eq('scan pre', AtlasPca.link_scan({ '$slot' => 'a', 'pre' => 5 }, { 'a' => {} }, []), 'placeholder pre must be a string')
      eq('scan post', AtlasPca.link_scan({ '$slot' => 'a', 'post' => 5 }, { 'a' => {} }, []), 'placeholder post must be a string')
      eq('scan in array', AtlasPca.link_scan([1, { '$slot' => 'zz' }], { 'a' => {} }, []), "placeholder names undeclared slot 'zz'")
      true
    end

    def small_helpers
      eq('js_string nil', AtlasPca.link_js_string(nil), 'null')
      eq('js_string 5', AtlasPca.link_js_string(5), '5')
      eq('js_string str', AtlasPca.link_js_string('s'), 's')
      eq('link_message non-ascii domain', AtlasPca.link_message("é", 'd'), "é".b + sha('d'))
      eq('link_message', AtlasPca.link_message(TSD, 'dg'), TSD + sha('dg'))
      true
    end

    # ------------------------------------------------------------------------------------ policy_link: signatures
    def signed_ok_cases
      calls = []
      sg = 's' * 64
      r = MutationKill::Seam.with(AtlasPca::Ed25519Strict, { verify: ->(pk, msg, sig) { calls << [pk, msg, sig]; true } }) do
        [AtlasPca.link_signed_ok?(pub, TSD, 'dg', b64u(sg)), AtlasPca.link_signed_ok?('bad', TSD, 'dg', b64u(sg)),
         AtlasPca.link_signed_ok?(pub, TSD, 'dg', 5), AtlasPca.link_signed_ok?(pub, TSD, 'dg', nil),
         AtlasPca.link_signed_ok?(pub, TSD, 'dg', 'short')]
      end
      eq('signed_ok seam results', r, [true, false, false, false, false])
      eq('signed_ok seam call', calls, [[KEY.raw_public_key, TSD + sha('dg'), sg]])
      good = b64u(KEY.sign(nil, TSD + sha('dg')))
      eq('signed_ok real', AtlasPca.link_signed_ok?(pub, TSD, 'dg', good), true)
      eq('signed_ok other digest', AtlasPca.link_signed_ok?(pub, TSD, 'dh', good), false)
      true
    end

    def verify_template_cases
      t0 = sign_t(tdef)
      boom = Object.new
      def boom.to_ary = raise('boom')
      zero = b64u("\0" * 64)
      eq('vt ok', AtlasPca.verify_template(t0, [pub]), { 'ok' => true })
      eq('vt nil', AtlasPca.verify_template(nil, [pub]), fail_h('template must be an object'))
      eq('vt array', AtlasPca.verify_template([], [pub]), fail_h('template must be an object'))
      eq('vt def error', AtlasPca.verify_template(t0.merge('def' => with { |x| x['v'] = 2 }), [pub]), fail_h('template v / kind mismatch'))
      eq('vt untrusted', AtlasPca.verify_template(t0, []), fail_h('template signer is not trusted'))
      eq('vt trusted nil', AtlasPca.verify_template(t0, nil), fail_h('template signer is not trusted'))
      eq('vt signer 5', AtlasPca.verify_template(t0.merge('signer' => 5), [5]), fail_h('template signer is not trusted'))
      eq('vt signer missing', AtlasPca.verify_template(t0.reject { |k, _| k == 'signer' }, [nil]), fail_h('template signer is not trusted'))
      eq('vt zero sig', AtlasPca.verify_template(t0.merge('sig' => zero), [pub]), fail_h('bad template signature'))
      eq('vt nil sig', AtlasPca.verify_template(t0.merge('sig' => nil), [pub]), fail_h('bad template signature'))
      eq('vt 5 sig', AtlasPca.verify_template(t0.merge('sig' => 5), [pub]), fail_h('bad template signature'))
      eq('vt other key', AtlasPca.verify_template(sign_t(tdef, KEY2).merge('signer' => pub), [pub]), fail_h('bad template signature'))
      eq('vt wrong domain', AtlasPca.verify_template(sign_t(tdef, KEY, TTD), [pub]), fail_h('bad template signature'))
      eq('vt edited', AtlasPca.verify_template(t0.merge('def' => with { |x| x['version'] = '2' }), [pub]), fail_h('bad template signature'))
      eq('vt rescue', AtlasPca.verify_template(t0, boom), fail_h('template verification error (fail closed)'))
      true
    end

    def tighten_base = { 'v' => 1, 'kind' => 'pca-template-tighten', 'template_id' => 'tpl', 'version_digest' => 'd' }

    def verify_tighten_cases
      o0 = sign_o(tighten_base)
      boom = Object.new
      def boom.to_ary = raise('boom')
      zero = b64u("\0" * 64)
      eq('vo ok', AtlasPca.verify_tighten(o0, [pub]), { 'ok' => true })
      eq('vo nil', AtlasPca.verify_tighten(nil, [pub]), fail_h('overlay must be an object'))
      eq('vo array', AtlasPca.verify_tighten([], [pub]), fail_h('overlay must be an object'))
      eq('vo error', AtlasPca.verify_tighten(o0.merge('overlay' => tighten_base.merge('v' => 2)), [pub]), fail_h('overlay v / kind mismatch'))
      eq('vo untrusted', AtlasPca.verify_tighten(o0, []), fail_h('overlay signer is not trusted'))
      eq('vo trusted nil', AtlasPca.verify_tighten(o0, nil), fail_h('overlay signer is not trusted'))
      eq('vo signer 5', AtlasPca.verify_tighten(o0.merge('signer' => 5), [5]), fail_h('overlay signer is not trusted'))
      eq('vo zero sig', AtlasPca.verify_tighten(o0.merge('sig' => zero), [pub]), fail_h('bad overlay signature'))
      eq('vo nil sig', AtlasPca.verify_tighten(o0.merge('sig' => nil), [pub]), fail_h('bad overlay signature'))
      eq('vo other key', AtlasPca.verify_tighten(sign_o(tighten_base, KEY2).merge('signer' => pub), [pub]), fail_h('bad overlay signature'))
      eq('vo wrong domain', AtlasPca.verify_tighten(sign_o(tighten_base, KEY, TSD), [pub]), fail_h('bad overlay signature'))
      eq('vo edited', AtlasPca.verify_tighten(o0.merge('overlay' => tighten_base.merge('version_digest' => 'e')), [pub]), fail_h('bad overlay signature'))
      eq('vo rescue', AtlasPca.verify_tighten(o0, boom), fail_h('overlay verification error (fail closed)'))
      true
    end

    def tighten_error_cases
      b = -> { tighten_base }
      idm = 'overlay template_id invalid'
      vdm = 'overlay version_digest invalid'
      awm = 'overlay add_where must be a list of conditions'
      acm = 'overlay add_caveats must be a list of caveats'
      [
        ['nil', nil, 'overlay must be an object'], ['array', [], 'overlay must be an object'], ['string', 'x', 'overlay must be an object'],
        ['ok', b.call, nil],
        ['v2', b.call.merge('v' => 2), 'overlay v / kind mismatch'],
        ['kind', b.call.merge('kind' => 'other'), 'overlay v / kind mismatch'],
        ['kind missing', b.call.reject { |k, _| k == 'kind' }, 'overlay v / kind mismatch'],
        ['unknown', b.call.merge('x' => 1), "overlay has unknown member 'x' (an overlay can only add where conditions and caveats)"],
        ['tid 5', b.call.merge('template_id' => 5), idm], ['tid Bad', b.call.merge('template_id' => 'Bad'), idm],
        ['tid nil', b.call.merge('template_id' => nil), idm],
        ['vd 5', b.call.merge('version_digest' => 5), vdm], ['vd empty', b.call.merge('version_digest' => ''), vdm],
        ['vd nil', b.call.merge('version_digest' => nil), vdm],
        ['aw string', b.call.merge('add_where' => 'x'), awm], ['aw nil', b.call.merge('add_where' => nil), awm],
        ['aw [1]', b.call.merge('add_where' => [1]), awm], ['aw ok', b.call.merge('add_where' => [{}]), nil],
        ['aw empty ok', b.call.merge('add_where' => []), nil],
        ['ac string', b.call.merge('add_caveats' => 'x'), acm], ['ac nil', b.call.merge('add_caveats' => nil), acm],
        ['ac [1]', b.call.merge('add_caveats' => [1]), acm], ['ac no type', b.call.merge('add_caveats' => [{}]), acm],
        ['ac type 5', b.call.merge('add_caveats' => [{ 'type' => 5 }]), acm],
        ['ac ok', b.call.merge('add_caveats' => [{ 'type' => 't' }]), nil]
      ].each { |label, o, want| eq("tighten_overlay_error #{label}", AtlasPca.tighten_overlay_error(o), want) }
      true
    end

    # ------------------------------------------------------------------------------------ policy_link: instantiation
    def slot_value_cases
      str = { 'type' => 'string' }
      int = { 'type' => 'integer' }
      set = { 'type' => 'set' }
      range = { 'type' => 'integer', 'min' => 2, 'max' => 4 }
      ms = "slot 'n' must be a string of 1..256 characters"
      mi = "slot 'n' must be a safe integer"
      mset = "slot 'n' must be a non-empty list of strings"
      ids = ->(n) { (0...n).map(&:to_s) }
      [
        [str, 'a', nil], [str, '', ms], [str, 5, ms], [str, nil, ms], [str, 'x' * 256, nil], [str, 'x' * 257, ms],
        [{ 'type' => 'string', 'values' => ['a'] }, 'a', nil],
        [{ 'type' => 'string', 'values' => ['a'] }, 'b', "slot 'n' is outside its closed value set"],
        [int, 3, nil], [int, 1.5, mi], [int, '3', mi], [int, -0.0, mi], [int, 2**53, mi],
        [range, 2, nil], [range, 4, nil], [range, 1, "slot 'n' is below its minimum"], [range, 5, "slot 'n' is above its maximum"],
        [set, ['a'], nil], [set, [], mset], [set, 'x', mset], [set, 5, mset], [set, [1], mset],
        [set, ids.call(64), nil], [set, ids.call(65), mset], [set, %w[a a], "slot 'n' has duplicate members"],
        [{ 'type' => 'set', 'values' => %w[a b] }, %w[a c], "slot 'n' has a member outside its closed set"],
        [{ 'type' => 'set', 'values' => %w[a b] }, %w[a b], nil]
      ].each_with_index { |(d, v, want), i| eq("link_slot_value_error ##{i} #{v.inspect[0, 30]}", AtlasPca.link_slot_value_error('n', d, v), want) }
      true
    end

    def matcher_cases
      wild = "slot 'n' would inject a wildcard or regex matcher into a verb or resource"
      duck = Object.new
      def duck.to_a = ['a*']
      [['a', nil], ['a*', wild], ['re:x', wild], [['ok', 'b*'], wild], [%w[ok re:y], wild], [%w[ok fine], nil], [5, nil], [nil, nil],
       [duck, nil], [['x', 5], nil]].each do |v, want|
        eq("link_matcher_safe #{v.inspect[0, 30]}", refusal { AtlasPca.link_matcher_safe('n', v) }, want)
      end
      true
    end

    def fill_cases
      s = { 's' => 'v' }
      ph = { '$slot' => 's' }
      eq('fill placeholder', AtlasPca.link_fill(ph, s), 'v')
      eq('fill 5', AtlasPca.link_fill(5, s), 5)
      eq('fill string', AtlasPca.link_fill('str', s), 'str')
      eq('fill nil', AtlasPca.link_fill(nil, s), nil)
      eq('fill array', AtlasPca.link_fill([ph, 1], s), ['v', 1])
      eq('fill hash', AtlasPca.link_fill({ 'k' => ph }, s), { 'k' => 'v' })
      eq('fill wildcard outside verb/resource', AtlasPca.link_fill({ 'value' => ph }, { 's' => 'a*' }), { 'value' => 'a*' })
      eq('fill regex outside verb/resource', AtlasPca.link_fill({ 'value' => ph }, { 's' => 're:x' }), { 'value' => 're:x' })
      wild = "slot 's' would inject a wildcard or regex matcher into a verb or resource"
      eq('fill verb wildcard', refusal { AtlasPca.link_fill({ 'verb' => ph }, { 's' => 'a*' }) }, wild)
      eq('fill resource regex', refusal { AtlasPca.link_fill({ 'resource' => ph }, { 's' => 're:x' }) }, wild)
      eq('fill verb in array', refusal { AtlasPca.link_fill({ 'verb' => [ph] }, { 's' => %w[ok b*] }) }, wild)
      eq('fill resource in array', refusal { AtlasPca.link_fill({ 'resource' => [ph] }, { 's' => 'a*' }) }, wild)
      eq('fill verb ok', AtlasPca.link_fill({ 'verb' => ph }, { 's' => %w[x y] }), { 'verb' => %w[x y] })
      eq('fill pre', AtlasPca.link_fill({ '$slot' => 's', 'pre' => '/a/' }, s), '/a/v')
      eq('fill post', AtlasPca.link_fill({ '$slot' => 's', 'post' => '/z' }, s), 'v/z')
      eq('fill both', AtlasPca.link_fill({ '$slot' => 's', 'pre' => '/a/', 'post' => '/z' }, s), '/a/v/z')
      eq('fill non-string affixes are empty', AtlasPca.link_fill({ '$slot' => 's', 'pre' => 5, 'post' => 5 }, { 's' => 7 }), 7)
      eq('fill non-string pre only', AtlasPca.link_fill({ '$slot' => 's', 'pre' => 5 }, s), 'v')
      eq('fill non-string post only', AtlasPca.link_fill({ '$slot' => 's', 'post' => 5 }, s), 'v')
      sp = "slot 's' cannot be spliced into a string (wildcard or non-string)"
      eq('splice number', refusal { AtlasPca.link_fill({ '$slot' => 's', 'pre' => '/a/' }, { 's' => 5 }) }, sp)
      eq('splice wildcard', refusal { AtlasPca.link_fill({ '$slot' => 's', 'pre' => '/a/' }, { 's' => 'a*' }) }, sp)
      eq('splice nul', refusal { AtlasPca.link_fill({ '$slot' => 's', 'post' => '/a' }, { 's' => "a\0b" }) }, sp)
      rx = "slot 's' would inject a regex matcher"
      eq('splice regex via post', refusal { AtlasPca.link_fill({ '$slot' => 's', 'post' => 'z' }, { 's' => 're:a' }) }, rx)
      eq('splice benign post', AtlasPca.link_fill({ '$slot' => 's', 'post' => 'z' }, { 's' => 'a' }), 'az')
      eq('splice regex-looking pre is the author\'s', AtlasPca.link_fill({ '$slot' => 's', 'pre' => 're:' }, { 's' => 'a' }), 're:a')
      true
    end

    def rich_def
      with do |x|
        x['slots'] = { 'a' => { 'type' => 'string' }, 'n' => { 'type' => 'integer', 'min' => 1, 'max' => 5 },
                       's' => { 'type' => 'set', 'values' => %w[x y z] } }
        x['body'] = { 'predicates' => [{ 'verb' => { '$slot' => 's' }, 'resource' => { '$slot' => 'a', 'pre' => '/r/' },
                                         'where' => [{ 'field' => 'f', 'op' => 'lte', 'value' => { '$slot' => 'n' } }] }] }
      end
    end

    def instantiate_cases
      d = rich_def
      fill = { 'a' => 'v', 'n' => 3, 's' => %w[x y] }
      want = { 'ok' => true, 'policy' => { 'predicates' => [{ 'verb' => %w[x y], 'resource' => '/r/v',
                                                              'where' => [{ 'field' => 'f', 'op' => 'lte', 'value' => 3 }] }],
                                           'caveats' => [] } }
      eq('inst ok', AtlasPca.instantiate_template(d, fill), want)
      with_cav = with(d) { |x| x['body']['caveats'] = [{ 'type' => 'rate' }] }
      eq('inst caveats', AtlasPca.instantiate_template(with_cav, fill)['policy']['caveats'], [{ 'type' => 'rate' }])
      eq('inst bad def', AtlasPca.instantiate_template(with(d) { |x| x['v'] = 2 }, fill), fail_h('template v / kind mismatch'))
      eq('inst nil def', AtlasPca.instantiate_template(nil, fill), fail_h('template must be an object'))
      [nil, [], 'x', 5].each { |s| eq("inst slots #{s.inspect}", AtlasPca.instantiate_template(d, s), fail_h('slots must be an object')) }
      eq('inst undeclared', AtlasPca.instantiate_template(d, fill.merge('zz' => 1)), fail_h("slot 'zz' is not declared by the template"))
      eq('inst unfilled', AtlasPca.instantiate_template(d, fill.reject { |k, _| k == 'n' }), fail_h("slot 'n' is not filled"))
      eq('inst bad value', AtlasPca.instantiate_template(d, fill.merge('n' => 9)), fail_h("slot 'n' is above its maximum"))
      eq('inst wildcard refusal', AtlasPca.instantiate_template(d, fill.merge('a' => 'q*')),
         fail_h("slot 'a' would inject a wildcard or regex matcher into a verb or resource"))
      r = MutationKill::Seam.with(AtlasPca, { link_fill: ->(*) { raise 'boom' } }) { AtlasPca.instantiate_template(d, fill) }
      eq('inst rescue', r, fail_h('instantiation error (fail closed)'))
      true
    end

    # ------------------------------------------------------------------------------------ policy_link: references
    def ref_error_cases
      ok = { 'template_id' => 'tpl', 'version_digest' => 'd', 'slots' => {} }
      tid = 'template_ref.template_id invalid'
      vd = 'template_ref.version_digest invalid'
      bd = 'template_ref.bind_params_digest invalid'
      bound = { 'template_id' => 'tpl', 'version_digest' => 'd', 'bind_params_digest' => 'p' }
      [
        ['nil', nil, 'template_ref must be an object'], ['array', [], 'template_ref must be an object'],
        ['string', 'x', 'template_ref must be an object'],
        ['ok', ok, nil], ['bound ok', bound, nil],
        ['unknown', ok.merge('x' => 1), "template_ref has unknown member 'x'"],
        ['tid 5', ok.merge('template_id' => 5), tid], ['tid Bad', ok.merge('template_id' => 'Bad'), tid],
        ['tid nil', ok.merge('template_id' => nil), tid],
        ['vd 5', ok.merge('version_digest' => 5), vd], ['vd empty', ok.merge('version_digest' => ''), vd],
        ['vd nil', ok.merge('version_digest' => nil), vd],
        ['vd 129', ok.merge('version_digest' => 'x' * 129), vd], ['vd 128', ok.merge('version_digest' => 'x' * 128), nil],
        ['both', ok.merge('bind_params_digest' => 'p'), 'template_ref has both slots and bind_params_digest'],
        ['bd empty', bound.merge('bind_params_digest' => ''), bd], ['bd 5', bound.merge('bind_params_digest' => 5), bd],
        ['bd nil', bound.merge('bind_params_digest' => nil), bd], ['bd 129', bound.merge('bind_params_digest' => 'x' * 129), bd],
        ['bd 128', bound.merge('bind_params_digest' => 'x' * 128), nil],
        ['slots array', ok.merge('slots' => []), 'template_ref.slots must be an object'],
        ['slots nil', ok.merge('slots' => nil), 'template_ref.slots must be an object'],
        ['neither', ok.reject { |k, _| k == 'slots' }, 'template_ref.slots must be an object']
      ].each { |label, r, want| eq("template_ref_error #{label}", AtlasPca.template_ref_error(r), want) }
      true
    end

    def resolve_fixture
      d = tdef
      g = dig(d)
      reg = { 'templates' => { g => sign_t(d) }, 'trusted' => [pub] }
      ref = { 'template_id' => 'tpl', 'version_digest' => g, 'slots' => { 'a' => 'v' } }
      [d, g, reg, ref]
    end

    def ov_for(g, extra, k = KEY) = sign_o({ 'v' => 1, 'kind' => 'pca-template-tighten', 'template_id' => 'tpl', 'version_digest' => g }.merge(extra), k)

    def resolve_real_cases
      _, g, reg, ref = resolve_fixture
      base = { 'predicates' => [{ 'verb' => 'x.y', 'resource' => '/r/v' }], 'caveats' => [] }
      eq('resolve ok', AtlasPca.resolve_link(ref, reg), { 'ok' => true, 'policy' => base, 'overlays' => 0 })
      cond = { 'field' => 'f', 'op' => 'eq', 'value' => 1 }
      o_a = ov_for(g, { 'add_where' => [cond] })
      want = { 'ok' => true, 'overlays' => 1,
               'policy' => { 'predicates' => [{ 'verb' => 'x.y', 'resource' => '/r/v', 'where' => [cond] }], 'caveats' => [] } }
      eq('resolve overlay where', AtlasPca.resolve_link(ref, reg.merge('overlays' => [o_a])), want)
      eq('resolve overlay tampered sig', AtlasPca.resolve_link(ref, reg.merge('overlays' => [o_a.merge('sig' => b64u("\0" * 64))])),
         fail_h('bad overlay signature'))
      true
    end

    def resolve_stub_cases
      d, g, reg, ref = resolve_fixture
      base = { 'predicates' => [{ 'verb' => 'x.y', 'resource' => '/r/v' }], 'caveats' => [] }
      cond = { 'field' => 'f', 'op' => 'eq', 'value' => 1 }
      cav = { 'type' => 't' }
      o_a = ov_for(g, { 'add_where' => [cond] })
      o_b = ov_for(g, { 'add_caveats' => [cav] })
      pred = ->(w) { { 'verb' => 'x.y', 'resource' => '/r/v', 'where' => w } }
      stub = ->(&blk) { MutationKill::Seam.with(AtlasPca::Ed25519Strict, { verify: ->(*) { true } }, &blk) }
      stub.call do
        eq('resolve caveats only overlay', AtlasPca.resolve_link(ref, reg.merge('overlays' => [o_b])),
           { 'ok' => true, 'policy' => { 'predicates' => [pred.call([])], 'caveats' => [cav] }, 'overlays' => 1 })
        eq('resolve two overlays', AtlasPca.resolve_link(ref, reg.merge('overlays' => [o_a, o_b])),
           { 'ok' => true, 'policy' => { 'predicates' => [pred.call([cond])], 'caveats' => [cav] }, 'overlays' => 2 })
        eq('resolve same overlay twice', AtlasPca.resolve_link(ref, reg.merge('overlays' => [o_a, o_a])),
           { 'ok' => true, 'policy' => { 'predicates' => [pred.call([cond, cond])], 'caveats' => [] }, 'overlays' => 2 })
        other = sign_o({ 'v' => 1, 'kind' => 'pca-template-tighten', 'template_id' => 'tpl', 'version_digest' => 'other', 'add_where' => [cond] })
        other_id = sign_o({ 'v' => 1, 'kind' => 'pca-template-tighten', 'template_id' => 'oth', 'version_digest' => g, 'add_where' => [cond] })
        junk = [nil, true, [], 'x', {}, { 'overlay' => 5 }, { 'overlay' => nil }, { 'overlay' => [] }, other, other_id, o_a]
        eq('resolve junk overlays are skipped', AtlasPca.resolve_link(ref, reg.merge('overlays' => junk)),
           { 'ok' => true, 'policy' => { 'predicates' => [pred.call([cond])], 'caveats' => [] }, 'overlays' => 1 })
        eq('resolve overlays nil', AtlasPca.resolve_link(ref, reg.merge('overlays' => nil)), { 'ok' => true, 'policy' => base, 'overlays' => 0 })
        bad_ov = { 'overlay' => { 'v' => 1, 'kind' => 'pca-template-tighten', 'template_id' => 'tpl', 'version_digest' => g, 'bogus' => 1 },
                   'signer' => pub, 'sig' => 'x' }
        eq('resolve invalid overlay for this version', AtlasPca.resolve_link(ref, reg.merge('overlays' => [bad_ov])),
           fail_h("overlay has unknown member 'bogus' (an overlay can only add where conditions and caveats)"))
        eq('resolve untrusted overlay signer', AtlasPca.resolve_link(ref, reg.merge('overlays' => [ov_for(g, { 'add_where' => [cond] }, KEY2)])),
           fail_h('overlay signer is not trusted'))
        # bound parameters
        params = { 'a' => 'w' }
        pd = dig(params)
        bref = { 'template_id' => 'tpl', 'version_digest' => g, 'bind_params_digest' => pd }
        want_w = { 'ok' => true, 'policy' => { 'predicates' => [{ 'verb' => 'x.y', 'resource' => '/r/w' }], 'caveats' => [] }, 'overlays' => 0 }
        eq('resolve bound', AtlasPca.resolve_link(bref, reg.merge('params' => { pd => params })), want_w)
        na = fail_h('parameter object is not available')
        eq('resolve bound no params', AtlasPca.resolve_link(bref, reg), na)
        eq('resolve bound params array', AtlasPca.resolve_link(bref, reg.merge('params' => [])), na)
        eq('resolve bound params string', AtlasPca.resolve_link(bref, reg.merge('params' => 'x')), na)
        eq('resolve bound param not a hash', AtlasPca.resolve_link(bref, reg.merge('params' => { pd => 'str' })), na)
        eq('resolve bound edited', AtlasPca.resolve_link(bref, reg.merge('params' => { pd => { 'a' => 'x' } })),
           fail_h('parameter object does not match bind_params_digest'))
        # refusals
        eq('resolve nil ref', AtlasPca.resolve_link(nil, reg), fail_h('template_ref must be an object'))
        eq('resolve bad ref', AtlasPca.resolve_link(ref.merge('x' => 1), reg), fail_h("template_ref has unknown member 'x'"))
        eq('resolve unknown version', AtlasPca.resolve_link(ref.merge('version_digest' => 'zz'), reg),
           fail_h('template version is not in the registry'))
        eq('resolve untrusted template', AtlasPca.resolve_link(ref, reg.merge('trusted' => [])), fail_h('template signer is not trusted'))
        eq('resolve digest mismatch', AtlasPca.resolve_link(ref.merge('version_digest' => 'X'), reg.merge('templates' => { 'X' => sign_t(d) })),
           fail_h('registry entry does not match its digest'))
        eq('resolve id mismatch', AtlasPca.resolve_link(ref.merge('template_id' => 'other'), reg),
           fail_h('template id does not match the reference'))
        eq('resolve bad fill', AtlasPca.resolve_link(ref.merge('slots' => {}), reg), fail_h("slot 'a' is not filled"))
        eq('resolve empty registry', AtlasPca.resolve_link(ref, {}), fail_h('link resolution error (fail closed)'))
        eq('resolve nil registry', AtlasPca.resolve_link(ref, nil), fail_h('link resolution error (fail closed)'))
      end
      r = MutationKill::Seam.with(AtlasPca, { verify_template: ->(*) { { 'ok' => false } } }) { AtlasPca.resolve_link(ref, reg) }
      eq('resolve template refused', r, fail_h('template refused'))
      r = stub.call do
        MutationKill::Seam.with(AtlasPca, { verify_tighten: ->(*) { { 'ok' => false } } }) { AtlasPca.resolve_link(ref, reg.merge('overlays' => [o_a])) }
      end
      eq('resolve overlay refused', r, fail_h('overlay refused'))
      true
    end

    # ------------------------------------------------------------------------------------ policy_classes
    def pc_valid(cls = 'org') = { 'class' => cls, 'revision' => 0, 'digest' => 'd', 'decision' => 'allow' }

    def pc_error_cases
      duck = Object.new
      def duck.to_str
        'org'
      end

      def duck.==(other)
        other == 'org'
      end
      all5 = %w[constitution regulatory org blueprint user].map { |c| pc_valid(c) }
      pre = ->(i) { "policy_classes[#{i}]" }
      [
        ['string', 'x', 'policy classes must be an array'], ['nil', nil, 'policy classes must be an array'],
        ['hash', {}, 'policy classes must be an array'],
        ['empty', [], nil], ['five', all5, nil], ['six', all5 + [pc_valid('org')], 'more than 5 policy classes'],
        ['not object', [5], "#{pre.call(0)} must be an object"], ['not object 2nd', [pc_valid, nil], "#{pre.call(1)} must be an object"],
        ['unknown member', [pc_valid.merge('extra' => 1)], "#{pre.call(0)} has unknown member 'extra'"],
        ['class 5', [pc_valid.merge('class' => 5)], "#{pre.call(0)}.class is not a known class"],
        ['class bogus', [pc_valid.merge('class' => 'bogus')], "#{pre.call(0)}.class is not a known class"],
        ['class nil', [pc_valid.merge('class' => nil)], "#{pre.call(0)}.class is not a known class"],
        ['class duck', [pc_valid.merge('class' => duck)], "#{pre.call(0)}.class is not a known class"],
        ['twice', [pc_valid, pc_valid], "policy class 'org' appears twice"],
        ['revision -1', [pc_valid.merge('revision' => -1)], "#{pre.call(0)}.revision must be a non-negative safe integer"],
        ['revision 1.5', [pc_valid.merge('revision' => 1.5)], "#{pre.call(0)}.revision must be a non-negative safe integer"],
        ['revision string', [pc_valid.merge('revision' => '1')], "#{pre.call(0)}.revision must be a non-negative safe integer"],
        ['revision nil', [pc_valid.merge('revision' => nil)], "#{pre.call(0)}.revision must be a non-negative safe integer"],
        ['revision 2^53', [pc_valid.merge('revision' => 2**53)], "#{pre.call(0)}.revision must be a non-negative safe integer"],
        ['revision 0', [pc_valid.merge('revision' => 0)], nil], ['revision max', [pc_valid.merge('revision' => (2**53) - 1)], nil],
        ['digest 5', [pc_valid.merge('digest' => 5)], "#{pre.call(0)}.digest invalid"],
        ['digest nil', [pc_valid.merge('digest' => nil)], "#{pre.call(0)}.digest invalid"],
        ['digest empty', [pc_valid.merge('digest' => '')], "#{pre.call(0)}.digest invalid"],
        ['digest 129', [pc_valid.merge('digest' => 'x' * 129)], "#{pre.call(0)}.digest invalid"],
        ['digest 128', [pc_valid.merge('digest' => 'x' * 128)], nil],
        ['digest 1', [pc_valid.merge('digest' => 'x')], nil],
        ['decision maybe', [pc_valid.merge('decision' => 'maybe')], "#{pre.call(0)}.decision must be allow, escalate or deny"],
        ['decision nil', [pc_valid.merge('decision' => nil)], "#{pre.call(0)}.decision must be allow, escalate or deny"],
        ['decision deny', [pc_valid.merge('decision' => 'deny')], nil], ['decision escalate', [pc_valid.merge('decision' => 'escalate')], nil]
      ].each { |label, l, want| eq("class_verdicts_error #{label}", AtlasPca.class_verdicts_error(l), want) }
      true
    end

    def pc_decide_cases
      none = ->(r) { { 'decision' => 'deny', 'classes' => [], 'denied_by' => [], 'escalated_by' => [], 'reason' => r } }
      eq('decide empty', AtlasPca.decide_classes([]), none.call('no_policy_class'))
      eq('decide 5', AtlasPca.decide_classes(5), none.call('malformed policy classes: policy classes must be an array'))
      eq('decide nil', AtlasPca.decide_classes(nil), none.call('malformed policy classes: policy classes must be an array'))
      eq('decide malformed', AtlasPca.decide_classes([pc_valid.merge('decision' => 'x')]),
         none.call('malformed policy classes: policy_classes[0].decision must be allow, escalate or deny'))
      u = pc_valid('user').merge('revision' => 3, 'digest' => 'u')
      o = pc_valid('org').merge('decision' => 'escalate', 'digest' => 'o')
      c = pc_valid('constitution').merge('decision' => 'deny', 'digest' => 'c')
      eq('decide meet', AtlasPca.decide_classes([u, o, c]),
         { 'decision' => 'deny', 'classes' => [c, o, u], 'denied_by' => ['constitution'], 'escalated_by' => ['org'] })
      eq('decide escalate', AtlasPca.decide_classes([u, o]),
         { 'decision' => 'escalate', 'classes' => [o, u], 'denied_by' => [], 'escalated_by' => ['org'] })
      eq('decide allow', AtlasPca.decide_classes([u]), { 'decision' => 'allow', 'classes' => [u], 'denied_by' => [], 'escalated_by' => [] })
      eq('decide drops nothing but keeps only the four members',
         AtlasPca.decide_classes([u.merge('x' => 1)]), none.call("malformed policy classes: policy_classes[0] has unknown member 'x'"))
      r = MutationKill::Seam.with(AtlasPca, { meet_all: ->(*) { raise 'boom' } }) { AtlasPca.decide_classes([u]) }
      eq('decide rescue', r, none.call('evaluation error (fail closed)'))
      true
    end

    # ------------------------------------------------------------------------------------ protect
    def prot(**o) = AtlasPca.protect(audience: 'aud', grants: [{ 'id' => 'g1' }], operation: ->(_e) {}, **o)

    def arg_error
      yield
      nil
    rescue ArgumentError => e
      e.message
    end

    def protect_cases
      ok = ->(_e) {}
      p = prot
      eq('revoke returns nil', p.revoke('g1'), nil)
      eq('revoke stores true', p.instance_variable_get(:@revoked), { 'g1' => true })
      f = prot.options[:authorize][:is_revoked]
      eq('not revoked', f.call(nil, { 'id' => 'g1' }), false)
      pr = prot
      f = pr.options[:authorize][:is_revoked]
      pr.revoke('g1')
      eq('revoked is exactly true', f.call(nil, { 'id' => 'g1' }), true)
      eq('other id not revoked', f.call(nil, { 'id' => 'g2' }), false)
      [nil, 5, [], 'str', {}, { 'id' => nil }].each { |g| eq("grant #{g.inspect} is refused", f.call(nil, g), true) }
      # an extra revocation source
      seen = []
      extra = ->(pc, g) { seen << [pc, g]; 'user-verdict' }
      p2 = prot(is_revoked: extra)
      f2 = p2.options[:authorize][:is_revoked]
      eq('extra source verdict', f2.call('pc', { 'id' => 'g2' }), 'user-verdict')
      eq('extra source args', seen, [['pc', { 'id' => 'g2' }]])
      p2.revoke('g2')
      seen.clear
      eq('revoked skips the extra source', f2.call('pc', { 'id' => 'g2' }), true)
      eq('extra source not consulted', seen, [])
      # authorize: { is_revoked: } is the source when the keyword is absent; the keyword wins
      p3 = prot(authorize: { is_revoked: ->(_pc, _g) { 'from-authorize' } })
      eq('authorize is_revoked used', p3.options[:authorize][:is_revoked].call(nil, { 'id' => 'g9' }), 'from-authorize')
      p4 = prot(is_revoked: ->(_pc, _g) { 'kw' }, authorize: { is_revoked: ->(_pc, _g) { 'from-authorize' } })
      eq('keyword wins', p4.options[:authorize][:is_revoked].call(nil, { 'id' => 'g9' }), 'kw')
      # the top-level authorize keys are folded into authorize:
      m = AtlasPca::MemoryStateStore.new
      eq('state_store kept', prot(state_store: m).options[:authorize][:state_store], m)
      # argument errors, exact messages
      eq('grants 5', arg_error { AtlasPca.protect(audience: 'a', grants: 5, operation: ok) },
         'grants: must be an Array of grants or a callable grant_ref -> grant')
      gm = 'grants: every grant must be a Hash with a String "id"'
      [nil, 5, 'id', [], { 'id' => 5 }, {}].each do |g|
        eq("grant #{g.inspect}", arg_error { AtlasPca.protect(audience: 'a', grants: [g], operation: ok) }, gm)
      end
      eq('operation 5', arg_error { AtlasPca.protect(audience: 'a', grants: [], operation: 5) }, 'operation: must respond to #call')
      eq('is_revoked 5', arg_error { AtlasPca.protect(audience: 'a', grants: [], operation: ok, is_revoked: 5) }, 'is_revoked: must respond to #call')
      am = "authorize: must be a Hash (use protect's own keywords for the rest)"
      eq('authorize 5', arg_error { AtlasPca.protect(audience: 'a', grants: [], operation: ok, authorize: 5) }, am)
      eq('authorize array', arg_error { AtlasPca.protect(audience: 'a', grants: [], operation: ok, authorize: []) }, am)
      # resolver
      g = { 'id' => 'a', 'x' => 1 }
      res = AtlasPca.protect_resolver([g])
      eq('resolver hit', res.call('a'), g)
      eq('resolver miss', res.call('b'), nil)
      callable = ->(r) { r }
      eq('resolver callable passthrough', AtlasPca.protect_resolver(callable).equal?(callable), true)
      true
    end

    # ------------------------------------------------------------------------------------ pca_grant
    def url_cases
      long = ->(n) { 'https://' + ('a' * (n - 8)) }
      [
        ['https://a', true], [5, false], [nil, false], [%w[https://a], false], ['http://a', false], ['https://a/b?c=d', true],
        ['https://a/!', true], ['https://a/~', true], ["https://a/\x7f", false], ["https://a/\x1f", false], ['https://a/ b', false],
        ['https://a/#x', false], ['https://a/\\x', false], ["https://a/é", false], ['https://', false], ['https:///x', false],
        ['https://?x', false], ['https://@h/x', false], ['https://u@h', false], ['https://@', false], ['https://h/p@q', true],
        ['https://h?q@r', true], ['https://h?q', true], ['https://h', true],
        [long.call(2048), true], [long.call(2049), false], [long.call(2047), true]
      ].each { |u, want| eq("pca_grant_https_url? #{u.inspect[0, 40]}", AtlasPca.pca_grant_https_url?(u), want) }
      true
    end

    def grant_detail
      { 'type' => 'pca_grant', 'chain_digest' => AtlasPca.pca_grant_chain_digest(['a']), 'chain_len' => 1 }
    end

    def grant_cases
      gd = grant_detail
      eight = (0...8).map { |i| "https://h#{i}" }
      [
        ['ok', gd, nil], ['locations ok', gd.merge('locations' => ['https://h']), nil], ['locations 8', gd.merge('locations' => eight), nil],
        ['locations 9', gd.merge('locations' => eight + ['https://h8']), 'bad_locations'],
        ['locations empty', gd.merge('locations' => []), 'bad_locations'], ['locations string', gd.merge('locations' => 'x'), 'bad_locations'],
        ['locations 5', gd.merge('locations' => 5), 'bad_locations'], ['locations nil', gd.merge('locations' => nil), 'bad_locations'],
        ['locations http', gd.merge('locations' => ['http://h']), 'bad_locations'],
        ['digest 5', gd.merge('chain_digest' => 5), 'bad_chain_digest'], ['digest short', gd.merge('chain_digest' => 'AAAA'), 'bad_chain_digest'],
        ['digest nil', gd.merge('chain_digest' => nil), 'bad_chain_digest']
      ].each { |label, d, want| eq("validate_pca_grant_detail #{label}", AtlasPca.validate_pca_grant_detail(d), want) }
      eq('parse 5', AtlasPca.parse_pca_grant_details(5), [nil, 'not_an_array'])
      eq('parse nil', AtlasPca.parse_pca_grant_details(nil), [nil, 'not_an_array'])
      eq('parse 17', AtlasPca.parse_pca_grant_details(Array.new(17) { gd }), [nil, 'too_many_details'])
      eq('parse 16', AtlasPca.parse_pca_grant_details(Array.new(16) { gd }), [Array.new(16) { gd }, nil])
      eq('parse nil element', AtlasPca.parse_pca_grant_details([nil]), [nil, 'bad_entry'])
      eq('parse string element', AtlasPca.parse_pca_grant_details(['type']), [nil, 'bad_entry'])
      eq('parse type 5', AtlasPca.parse_pca_grant_details([{ 'type' => 5 }]), [nil, 'bad_entry'])
      eq('parse other type skipped', AtlasPca.parse_pca_grant_details([{ 'type' => 'other' }]), [[], nil])
      eq('parse unknown member', AtlasPca.parse_pca_grant_details([gd.merge('x' => 1)]), [nil, 'unknown_member'])
      eq('parse mixed', AtlasPca.parse_pca_grant_details([{ 'type' => 'other' }, gd]), [[gd], nil])
      ids = %w[a b]
      d2 = { 'type' => 'pca_grant', 'chain_digest' => AtlasPca.pca_grant_chain_digest(ids), 'chain_len' => 2 }
      chk = ->(details, res, proof) { AtlasPca.check_pca_grant_presentation(details, res, ids, proof) }
      eq('check none', chk.call([], 'r', true), [nil, 'no_detail'])
      eq('check proof yes', chk.call([d2], 'r', 'yes'), [nil, 'proof_required'])
      eq('check proof nil', chk.call([d2], 'r', nil), [nil, 'proof_required'])
      eq('check ok', chk.call([d2], 'r', true), [0, nil])
      eq('check too long', chk.call([d2.merge('chain_len' => 3)], 'r', true), [nil, 'chain_mismatch'])
      eq('check digest mismatch', chk.call([d2.merge('chain_digest' => AtlasPca.pca_grant_chain_digest(%w[a c]))], 'r', true), [nil, 'chain_mismatch'])
      eq('check wrong location', chk.call([d2.merge('locations' => ['https://x'])], 'https://y', true), [nil, 'wrong_location'])
      eq('check right location', chk.call([d2.merge('locations' => ['https://x'])], 'https://x', true), [0, nil])
      d1 = { 'type' => 'pca_grant', 'chain_digest' => AtlasPca.pca_grant_chain_digest(['a']), 'chain_len' => 1 }
      eq('check second detail', chk.call([d2.merge('chain_len' => 3), d1], 'r', true), [1, nil])
      eq('check wrong location then mismatch', chk.call([d2.merge('locations' => ['https://x']), d2.merge('chain_len' => 3)], 'https://y', true),
         [nil, 'wrong_location'])
      eq('check wrong location then match', chk.call([d2.merge('locations' => ['https://x']), d1], 'https://y', true), [1, nil])
      true
    end

    # ------------------------------------------------------------------------------------ runtime_claim
    class RcDuck
      def initialize(h)
        @h = h
      end

      def keys
        @h.keys
      end

      def [](k)
        @h[k]
      end

      def reject(&b)
        @h.reject(&b)
      end
    end

    def claim(over = {}, key = KEY)
      body = { 'v' => 1, 'class' => 'os_confined', 'passport_digest' => 'pd', 'evidence_digest' => 'ed', 'iat' => 10, 'exp' => 20,
               'attestor' => pub(key) }.merge(over)
      body.merge('sig' => b64u(key.sign(nil, RCD + AtlasPca.canon_bytes(body))))
    end

    def rc(c, pinned: [pub], pd: 'pd', ev: ['ed'], now: 15) = AtlasPca.verified_runtime_class(c, pinned, pd, ev, now)

    def runtime_cases
      eq('rc ok', rc(claim), 'os_confined')
      %w[none os_confined egress_default_deny wasi_no_ambient].each { |c| eq("rc class #{c}", rc(claim('class' => c)), c) }
      eq('rc duck', rc(RcDuck.new(claim)), 'none')
      eq('rc nil', rc(nil), 'none')
      eq('rc array', rc([]), 'none')
      eq('rc extra member', rc(claim('extra' => 1)), 'none')
      eq('rc missing member', rc(claim.reject { |k, _| k == 'exp' }), 'none')
      # 1.0 == 1 but is no Integer (an integral float is not even canonical, so the signature check alone would also refuse it):
      # with the signature check stubbed to accept, only the Integer gate refuses.
      r = MutationKill::Seam.with(AtlasPca, { k3_verify_body: ->(*) { true } }) do
        [rc(claim.merge('v' => 1.0)), rc(claim), rc(claim.merge('v' => 2)), rc(claim.merge('class' => 'bogus'))]
      end
      eq('rc v 1.0 gate (signature stubbed)', r, ['none', 'os_confined', 'none', 'none'])
      eq('rc v 2', rc(claim('v' => 2)), 'none')
      eq('rc v string', rc(claim('v' => '1')), 'none')
      eq('rc class bogus', rc(claim('class' => 'bogus')), 'none')
      eq('rc class nil', rc(claim('class' => nil)), 'none')
      eq('rc passport 5', rc(claim('passport_digest' => 5), pd: 5), 'none')
      eq('rc passport empty', rc(claim('passport_digest' => ''), pd: ''), 'none')
      eq('rc passport 129', rc(claim('passport_digest' => 'x' * 129), pd: 'x' * 129), 'none')
      eq('rc passport 128', rc(claim('passport_digest' => 'x' * 128), pd: 'x' * 128), 'os_confined')
      eq('rc evidence 5', rc(claim('evidence_digest' => 5), ev: [5]), 'none')
      eq('rc evidence empty', rc(claim('evidence_digest' => ''), ev: ['']), 'none')
      eq('rc evidence 129', rc(claim('evidence_digest' => 'x' * 129), ev: ['x' * 129]), 'none')
      eq('rc evidence 128', rc(claim('evidence_digest' => 'x' * 128), ev: ['x' * 128]), 'os_confined')
      eq('rc iat negative', rc(claim('iat' => -1)), 'none')
      eq('rc exp float', rc(claim('exp' => 20.5)), 'none')
      eq('rc now float', rc(claim, now: 10.5), 'none')
      eq('rc iat float', rc(claim('iat' => 10.5)), 'none')
      eq('rc now == iat', rc(claim, now: 10), 'os_confined')
      eq('rc now < iat', rc(claim, now: 9), 'none')
      eq('rc now == exp - 1', rc(claim, now: 19), 'os_confined')
      eq('rc now == exp', rc(claim, now: 20), 'none')
      eq('rc not pinned', rc(claim, pinned: []), 'none')
      eq('rc other pinned', rc(claim, pinned: [pub(KEY2)]), 'none')
      eq('rc passport mismatch', rc(claim, pd: 'zz'), 'none')
      eq('rc evidence unverified', rc(claim, ev: []), 'none')
      eq('rc evidence other', rc(claim, ev: ['other']), 'none')
      eq('rc sig nil', rc(claim.merge('sig' => nil)), 'none')
      eq('rc sig zero', rc(claim.merge('sig' => b64u("\0" * 64))), 'none')
      eq('rc sig of other key', rc(claim({}, KEY2).merge('attestor' => pub)), 'none')
      eq('rc body edited', rc(claim.merge('exp' => 21)), 'none')
      eq('rc pinned not a list', rc(claim, pinned: 5), 'none')
      calls = []
      orig = AtlasPca.method(:k3_str?)
      r = MutationKill::Seam.with(AtlasPca, { k3_str?: ->(x, m = 512) { calls << [x, m]; orig.call(x, m) } }) { rc(claim) }
      eq('rc k3_str? result', r, 'os_confined')
      eq('rc k3_str? caps', calls, [[pub, 128], ['pd', 128], ['ed', 128]])
      true
    end
  end

  t('c22 policy_link: template_def_error exact refusals') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.def_error_cases
  end
  t('c22 policy_link: link_scan, link_js_string, link_message') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.scan_cases && C22Ppg.small_helpers
  end
  t('c22 policy_link: link_signed_ok? (seam over Ed25519Strict.verify)') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.signed_ok_cases
  end
  t('c22 policy_link: verify_template exact results') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.verify_template_cases
  end
  t('c22 policy_link: verify_tighten exact results') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.verify_tighten_cases
  end
  t('c22 policy_link: tighten_overlay_error exact refusals') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.tighten_error_cases
  end
  t('c22 policy_link: slot values, matcher safety, fill') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.slot_value_cases && C22Ppg.matcher_cases && C22Ppg.fill_cases
  end
  t('c22 policy_link: instantiate_template exact results') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.instantiate_cases
  end
  t('c22 policy_link: template_ref_error exact refusals') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.ref_error_cases
  end
  t('c22 policy_link: resolve_link with a real signature') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.resolve_real_cases
  end
  t('c22 policy_link: resolve_link overlays, bound parameters, refusals') do
    next true if C22Ppg.skip?('policy_link.rb')

    C22Ppg.resolve_stub_cases
  end
  t('c22 policy_classes: class_verdicts_error and decide_classes exact') do
    next true if C22Ppg.skip?('policy_classes.rb')

    C22Ppg.pc_error_cases && C22Ppg.pc_decide_cases
  end
  t('c22 protect: revocation wiring, argument errors, resolver') do
    next true if C22Ppg.skip?('protect.rb')

    C22Ppg.protect_cases
  end
  t('c22 pca_grant: https url shape and byte bounds') do
    next true if C22Ppg.skip?('pca_grant.rb')

    C22Ppg.url_cases
  end
  t('c22 pca_grant: detail, array and presentation results') do
    next true if C22Ppg.skip?('pca_grant.rb')

    C22Ppg.grant_cases
  end
  t('c22 runtime_claim: verified_runtime_class every gate') do
    next true if C22Ppg.skip?('runtime_claim.rb')

    C22Ppg.runtime_cases
  end
end
