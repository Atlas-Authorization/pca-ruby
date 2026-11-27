# frozen_string_literal: true

require 'securerandom'
require 'digest'
require 'openssl'
require 'base64'
require 'fileutils'
require_relative 'js_compat'
require_relative 'whatwg_url'
require_relative 'ada_idna'
require_relative 'private_file'

# A CIBA on-ramp for PCA's FROST step-up (OpenID CIBA Core 1.0), byte-identical to the TypeScript reference: the canonical
# approval action, the binding message and backchannel auth request (with the render match code), the tier-3 gate, the budget
# effect of a decision, the in-memory and durable approval brokers over versioned compare-and-set stores (memory, one JSON
# file, a string KV with a directory reference), a relying-party client for a real OP (POLL / PING, synchronous), and the PING
# callback check.
#
# A step-up is a String-keyed Hash with the reference's member names (id, verb, resource, params, tier, goalCommit, goal,
# render, renderDigest). Options are snake_case String-keyed Hashes: expires_in_sec, auth_req_id, step_up_scope, login_hint,
# binding_message ({max_chars, token_only}), interval, acts_for (+ for initiate: login_hint_token, id_token_hint, delivery,
# client_notification_token, acr_values, user_code). Produced records (auth request, session, flow, poll result) keep the
# reference's member names, so a record stored here reads the same in every implementation. Refusals raise ArgumentError
# (the reference's RangeError), TypeError, CibaProviderError (an OP answer) or ApprovalStoreError (a store fault, with #code).
# Nothing here authorises anything on its own: the resource server's verifier and the FROST cosigners remain the authority.
module AtlasPca
  module Ciba
    DEFAULT_EXPIRY_SEC = 300
    DEFAULT_INTERVAL_SEC = 5
    MIN_AUTH_REQ_ID_LEN = 22
    MAX_GOAL_CHARS = 100
    MAX_PAYEE_CHARS = 64
    PAYEE_KEYS = %w[payee to recipient beneficiary destination].freeze
    DISPLAYED_PARAM_KEYS = (%w[amount currency] + PAYEE_KEYS).freeze
    CIBA_GRANT = 'urn:openid:params:grant-type:ciba'
    SLOW_DOWN_STEP_SEC = 5
    MIN_NOTIFICATION_TOKEN_CHARS = 22
    MAX_NOTIFICATION_TOKEN_CHARS = 1024
    DEFAULT_TIMEOUT_MS = 30_000
    MAX_BACKOFF_MS = 60_000
    MAX_CONSECUTIVE_TRANSIENT = 5
    MAX_CAS_TRIES = 8

    WS = Js::WS
    WS_RE = /\A[#{WS}]\z/o
    WS_TWO = /[#{WS}]{2,}/o
    # JavaScript /because\s+you\s+asked/i: ASCII case folding only (Ruby's /i would also fold the long s and the Kelvin sign)
    FORGED_CLAUSE = /[Bb][Ee][Cc][Aa][Uu][Ss][Ee][#{WS}]+[Yy][Oo][Uu][#{WS}]+[Aa][Ss][Kk][Ee][Dd]/o
    AUTH_REQ_ID = /\A[A-Za-z0-9._-]+\z/
    SCOPE_TOKEN = /\A[\x21\x23-\x5B\x5D-\x7E]+\z/
    IDENT = %r{\A[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}\z}
    PLAIN_AMOUNT = /\A(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\z/
    CURRENCY = /\A[A-Za-z]{3}\z/
    ASCII_PRINTABLE = /\A[\x20-\x7E]*\z/
    ASCII_PRINTABLE1 = /\A[\x20-\x7E]+\z/
    NOTIFICATION_TOKEN = /\A[\x21-\x7E]+\z/
    UNDISPLAYABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\u2028\u2029\uFFF9-\uFFFD]/
    PLAIN_TEXT_CTRL = /[\p{Cc}\p{Cf}\u2028\u2029]/
    BEARER = /\A[Bb][Ee][Aa][Rr][Ee][Rr] +([^#{WS}]+)\z/o
    SCRIPT_GROUPS = [
      ['latin', /\p{Latin}/], ['cyrillic', /\p{Cyrillic}/], ['greek', /\p{Greek}/], ['armenian', /\p{Armenian}/],
      ['hebrew', /\p{Hebrew}/], ['arabic', /\p{Arabic}/], ['cjk', /[\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}\p{Bopomofo}]/],
      ['indic-thai', /[\p{Devanagari}\p{Bengali}\p{Tamil}\p{Thai}\p{Georgian}]/]
    ].freeze
    # one UTF-16-ish unit of a WTF-8 string: a character or a lone surrogate (3 bytes ED A0..BF xx)
    UNIT = /[\x00-\x7f]|[\xc0-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf7][\x80-\xbf]{3}|./nm

    # A refusal that carries the reference runtime's code (Node's ERR_INVALID_ARG_TYPE).
    class CodedError < ArgumentError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    # An error answer from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply. #retryable: a network error, timeout,
    # 5xx or a non-JSON reply; never a definitive OP answer.
    class CibaProviderError < StandardError
      attr_reader :error, :error_description, :status, :retryable

      def initialize(status, error, error_description = nil, retryable = false)
        super("ciba: provider returned #{status} #{error}#{error_description.nil? ? '' : " (#{error_description})"}")
        @status = status
        @error = error
        @error_description = error_description
        @retryable = retryable
      end
    end

    # Raised by the KV reference stores; #code is corrupt_record | lock_timeout | bad_key.
    class ApprovalStoreError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    module_function

    # ---- JavaScript string helpers (a String may carry lone surrogates as WTF-8) --------------------------------------------
    def units(s) = s.valid_encoding? ? s.chars : s.b.scan(UNIT).map { |u| u.force_encoding('UTF-8') }
    def cat(*parts) = parts.map(&:b).join.force_encoding('UTF-8')
    def rx?(re, s) = s.scrub("\u{FFFD}").match?(re)

    def cp(u)
      return u.ord if u.valid_encoding?

      b = u.bytes
      ((b[0] & 0x0f) << 12) | ((b[1] & 0x3f) << 6) | (b[2] & 0x3f)
    end

    # String#slice(0, n) in UTF-16 code units (an astral character cut in half leaves its high surrogate, as JavaScript does).
    def u16_prefix(s, n)
      out = []
      len = 0
      units(s).each do |u|
        break if len >= n

        c = cp(u)
        if c > 0xffff
          if len + 2 > n
            hi = 0xd800 + ((c - 0x10000) >> 10)
            out << [0xe0 | (hi >> 12), 0x80 | ((hi >> 6) & 0x3f), 0x80 | (hi & 0x3f)].pack('C*').force_encoding('UTF-8')
            len += 1
            break
          end
          len += 2
        else
          len += 1
        end
        out << u
      end
      cat(*out)
    end

    def finite?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    # Control, format (bidi, zero-width) and line-separator characters become spaces; whitespace runs collapse; trimmed.
    def plain_text(value)
      raise TypeError, 'value.replace is not a function' unless value.is_a?(String)

      out = []
      in_ws = false
      units(value).each do |u|
        u = ' ' if u.valid_encoding? && u.match?(PLAIN_TEXT_CTRL)
        if u.valid_encoding? && u.match?(WS_RE)
          out << ' ' unless in_ws
          in_ws = true
        else
          out << u
          in_ws = false
        end
      end
      out.shift while out.first == ' '
      out.pop while out.last == ' '
      cat(*out)
    end

    def clip(value, max)
      us = units(value)
      us.length <= max ? value : cat(*us[0, (max - 1).to_i], '…')
    end

    def identifier(value, what)
      unless value.is_a?(String) && rx?(IDENT, value)
        raise ArgumentError, "ciba: the step-up #{what} must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 " \
                             'characters); refusing to render free text in the approval message'
      end
      raise ArgumentError, "ciba: the step-up #{what} contains an approval-explanation clause" if rx?(FORGED_CLAUSE, value)

      value
    end

    def scripts_of(t)
      found = {}
      t.each_char do |ch|
        next unless ch.match?(/\p{L}/)

        g = SCRIPT_GROUPS.find { |_, re| ch.match?(re) }
        found[g ? g[0] : "other:#{ch}"] = true
      end
      found.keys
    end

    def payee_text(value)
      raise ArgumentError, 'ciba: the payee must be a string (a nested value cannot be shown to the approver)' unless value.is_a?(String)

      # a lone surrogate becomes U+FFFD, which is undisplayable too: the same refusal as the reference's \p{Cs}
      t = value.scrub("\u{FFFD}").unicode_normalize(:nfc)
      if t.empty? || Js.trim(t) != t || t.match?(WS_TWO)
        raise ArgumentError, 'ciba: the payee must be non-empty without leading, trailing or repeated whitespace'
      end
      if t.match?(UNDISPLAYABLE)
        raise ArgumentError, 'ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed'
      end
      raise ArgumentError, 'ciba: the payee must not contain quote or backslash characters' if t.match?(/["\\]/)
      if t.length > MAX_PAYEE_CHARS
        raise ArgumentError, "ciba: the payee is longer than #{MAX_PAYEE_CHARS} characters; refusing to truncate what the person approves"
      end
      raise ArgumentError, 'ciba: the payee contains an approval-explanation clause' if t.match?(FORGED_CLAUSE)
      # Look-alikes: a combining mark left after NFC is stacked or decorative; compatibility forms differ under NFKC; a payee
      # that mixes scripts is the classic homograph. One non-Latin script is allowed but shown with its ASCII form.
      raise ArgumentError, 'ciba: the payee contains combining marks and cannot be shown unambiguously' if t.match?(/\p{M}/)
      if t.unicode_normalize(:nfkc) != t
        raise ArgumentError, 'ciba: the payee contains compatibility/fullwidth characters that imitate plain ones'
      end
      if scripts_of(t).length > 1
        raise ArgumentError, 'ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike'
      end

      t
    end

    # ---- ASCII form of a payee (punycode) -----------------------------------------------------------------------------------
    def pdigit(d) = (d < 26 ? 97 + d : 22 + d).chr

    def adapt(delta, num_points, first)
      delta = first ? delta / 700 : delta / 2
      delta += delta / num_points
      k = 0
      while delta > 455
        delta /= 35
        k += 36
      end
      k + (36 * delta / (delta + 38))
    end

    # RFC 3492 punycode of one label (no xn-- prefix).
    def punycode(input)
      o = +''
      n = 128
      delta = 0
      bias = 72
      input.each { |c| o << c.chr if c < 128 }
      b = o.length
      h = b
      o << '-' if b.positive?
      while h < input.length
        m = input.select { |c| c >= n }.min
        delta += (m - n) * (h + 1)
        n = m
        input.each do |c|
          delta += 1 if c < n
          next unless c == n

          q = delta
          k = 36
          loop do
            t = if k <= bias then 1 elsif k >= bias + 26 then 26 else k - bias end
            break if q < t

            o << pdigit(t + ((q - t) % (36 - t)))
            q = (q - t) / (36 - t)
            k += 36
          end
          o << pdigit(q)
          bias = adapt(delta, h + 1, h == b)
          delta = 0
          h += 1
        end
        delta += 1
        n += 1
      end
      o
    end

    def idna_ignored?(c) = [0xad, 0x200b, 0x2060, 0xfeff].include?(c) || (0xfe00..0xfe0f).cover?(c) || (0x180b..0x180d).cover?(c)

    # shortcut (without ATLAS_PCA_LIBADA, see AdaIdna): an approximation of url.domainToASCII (the host of ws://<word>): the word ends at / ? # \, a valid %XX is
    # decoded, UTS 46 style mapping (lower case, NFKC, ideographic dots, ignored characters), per-label punycode, a numeric last
    # label (an IPv4 form) refused; '' when it cannot be encoded. Display-only (the ASCII form shown next to a payee); upgrade
    # to a full UTS 46 table if a payee ever needs the exact IDNA mapping.
    def domain_to_ascii(word)
      w = word.scrub("\u{FFFD}")
      return AdaIdna.domain_to_ascii(w) if AdaIdna.available? # the exact parser Node uses (opt-in: ATLAS_PCA_LIBADA)

      cut = w.index(%r{[/?#\\]})
      host = cut ? w[0, cut] : w
      return '' if host.empty?

      dec = host.b.gsub(/%([0-9A-Fa-f]{2})/n) { Regexp.last_match(1).hex.chr }.force_encoding('UTF-8').scrub("\u{FFFD}")
      low = dec.each_char.reject { |c| idna_ignored?(c.ord) }.map(&:downcase).join
      m = low.unicode_normalize(:nfkc).each_char.map(&:downcase).join.tr("\u3002\uFF0E\uFF61", '...')
      m.each_char do |c|
        o = c.ord
        if o < 0x80
          return '' if o <= 0x20 || o == 0x7f || '#%/:<>?@[\\]^|'.include?(c)
        elsif !c.match?(/[\p{L}\p{Nd}\p{M}]/)
          return ''
        end
      end
      labels = m.split('.', -1).map { |l| l.ascii_only? ? l : "xn--#{punycode(l.codepoints)}" }
      last = labels.length - 1
      last -= 1 if last.positive? && labels[last].empty?
      return '' if labels[last].match?(/\A[0-9]+\z/) || labels[last].match?(/\A0[xX][0-9a-fA-F]*\z/)

      labels.join('.')
    end

    # Plain-ASCII rendering of a payee: itself when ASCII, else the punycode of each word (\u{..} escapes when IDNA refuses).
    def ascii_form(payee)
      return payee if rx?(ASCII_PRINTABLE, payee)

      payee.b.split(' ', -1).map { |w| w.force_encoding('UTF-8') }.map do |w|
        next w if rx?(ASCII_PRINTABLE, w)

        a = domain_to_ascii(w)
        next a unless a.empty?

        units(w).map { |u| (c = cp(u)) > 0x7e ? "\\u{#{c.to_s(16)}}" : u }.join
      end.join(' ')
    end

    # ---- the canonical action and the binding message -----------------------------------------------------------------------

    # The canonical action shown to the approver. Fails loud: unknown params keys, a nested or malformed amount, a missing
    # currency or payee next to an amount, two payee fields, a non-identifier verb / resource.
    def ciba_action_from_step_up(step_up)
      raise TypeError, 'ciba: the step-up must be an object' unless step_up.is_a?(Hash)

      params = step_up['params'].nil? ? {} : step_up['params']
      raise ArgumentError, 'ciba: step-up params must be an object' unless params.is_a?(Hash)

      unknown = Js.js_keys(params).reject { |k| DISPLAYED_PARAM_KEYS.include?(k) }
      unless unknown.empty?
        raise ArgumentError, "ciba: step-up params field(s) #{unknown.join(', ')} are not displayed in the approval message (displayable: " \
                             "amount, currency, #{PAYEE_KEYS.join('/')}); refusing so the person never approves a hidden field"
      end
      action = { 'verb' => identifier(step_up['verb'], 'verb'), 'resource' => identifier(step_up['resource'], 'resource') }
      payee_keys = PAYEE_KEYS.reject { |k| params[k].nil? }
      if payee_keys.length > 1
        raise ArgumentError, "ciba: more than one payee field (#{payee_keys.join(', ')}) in params; the approver would see only one"
      end

      if !params['amount'].nil?
        amt = params['amount']
        text = if Js.num?(amt) && finite?(amt) then Js.string(amt) elsif amt.is_a?(String) then amt else '' end
        unless rx?(PLAIN_AMOUNT, text)
          raise ArgumentError, 'ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)'
        end

        cur = params['currency']
        unless cur.is_a?(String) && rx?(CURRENCY, cur)
          raise ArgumentError, 'ciba: the binding message needs a 3-letter currency code next to the amount'
        end
        if payee_keys.empty?
          raise ArgumentError, 'ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it'
        end

        action['amount'] = text
        action['currency'] = cur.upcase
      elsif !params['currency'].nil?
        raise ArgumentError, 'ciba: a currency without an amount cannot be displayed'
      end
      action['payee'] = payee_text(params[payee_keys[0]]) if payee_keys.length == 1
      action
    end

    def binding_message(step_up, acts_for, max_chars)
      a = ciba_action_from_step_up(step_up)
      head = +"Approve #{a['verb']}"
      head << " #{a['amount']} #{a['currency']}" if a.key?('amount')
      if a.key?('payee')
        head << " to \"#{a['payee']}\""
        head << " [non-ASCII name; ASCII form: #{ascii_form(a['payee'])}]" unless a['payee'].match?(ASCII_PRINTABLE)
      end
      head << " on #{a['resource']}"
      limit = max_chars.nil? ? Float::INFINITY : max_chars
      if head.length > limit
        raise ArgumentError, "ciba: the binding message needs #{head.length} characters but bindingMessage.maxChars is " \
                             "#{Js.string(max_chars)}; refusing to truncate what the person approves"
      end

      plain_goal = if step_up.key?('goal')
                     cat(*units(plain_text(step_up['goal'])).map { |u| ["'", "\u2018", "\u2019"].include?(u) ? "\u2032" : u })
                   else
                     ''
                   end
      goal_text = if !plain_goal.empty?
                    clip(plain_goal, MAX_GOAL_CHARS)
                  else
                    gc = step_up['goalCommit']
                    raise TypeError, "Cannot read properties of #{gc.nil? ? 'undefined' : 'null'} (reading 'length')" if gc.nil?

                    if gc.is_a?(String) then gc.empty? ? nil : cat('goal ', u16_prefix(gc, 10), '…')
                    elsif gc.is_a?(Array) then gc.empty? ? nil : "goal #{Js.string(gc[0, 10])}…"
                    end
                  end
      return head if goal_text.nil?

      prefix = cat(" \u2014 because you asked ", acts_for, " to '")
      room = limit - head.length - units(prefix).length - 1
      return cat(head, prefix, goal_text, "'") if room >= units(goal_text).length
      return cat(head, prefix, clip(goal_text, room), "'") if room >= 8

      head
    end

    def tokenise(value) = value.gsub(/[^A-Za-z0-9._-]+/, '-').gsub(/-{2,}/, '-').gsub(/\A[-.]+|[-.]+\z/, '')

    def compact_binding_message(step_up, max_chars)
      a = ciba_action_from_step_up(step_up)
      if a.key?('payee') && !a['payee'].match?(ASCII_PRINTABLE1)
        raise ArgumentError, 'ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)'
      end

      raw = ['Approve', a['verb']]
      raw += [a['amount'], a['currency']] if a.key?('amount')
      raw += ['to', a['payee']] if a.key?('payee')
      raw << a['resource']
      parts = raw.map { |p| tokenise(p) }
      raise ArgumentError, 'ciba: tokenOnly binding message cannot represent the verb, payee or resource' if parts.any?(&:empty?)

      out = parts.join('-')
      if out.length > max_chars
        raise ArgumentError, "ciba: the binding message needs #{out.length} characters but bindingMessage.maxChars is " \
                             "#{Js.string(max_chars)}; refusing to truncate what the person approves"
      end
      out
    end

    def int_of(v) = v.is_a?(Float) ? v.to_i : v

    # Map a step-up to a CIBA auth request. Pure: a stable auth_req_id derived from the step-up id (unless one is given), the
    # binding message, scope, expiry and poll interval. Starts nothing and notifies nobody.
    def to_ciba_auth_request(step_up, opts = {})
      raise TypeError, "Cannot read properties of null (reading 'actsFor')" if opts.nil? # a null options argument (the default only covers undefined)
      raise TypeError, 'ciba: the step-up must be an object' unless step_up.is_a?(Hash)

      o = opts.is_a?(Hash) ? opts : {}
      acts_for = 'your agent'
      if o.key?('acts_for')
        raise TypeError, "Cannot read properties of null (reading 'replace')" if o['acts_for'].nil?

        pt = plain_text(o['acts_for'])
        acts_for = clip(pt, 40) unless pt.empty?
      end
      expiry = o.key?('expires_in_sec') ? o['expires_in_sec'] : DEFAULT_EXPIRY_SEC
      unless Js.num?(expiry) && Js.safe_integer?(expiry) && expiry.positive?
        raise ArgumentError, "ciba: requested_expiry must be a positive integer number of seconds, got #{Js.string(expiry)}"
      end

      step_scope = cat('urn:atlas:pca:stepup:', Js.string(step_up['verb']))
      raise ArgumentError, 'ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)' unless rx?(SCOPE_TOKEN, step_scope)

      scope = o['step_up_scope'] == false ? 'openid' : "openid #{step_scope}"
      interval = o.key?('interval') ? o['interval'] : DEFAULT_INTERVAL_SEC
      unless Js.num?(interval) && Js.safe_integer?(interval) && interval.positive?
        raise ArgumentError, "ciba: interval must be a positive integer number of seconds, got #{Js.string(interval)}"
      end

      auth_req_id = o['auth_req_id']
      if auth_req_id.nil?
        d = { 'd' => 'atlas-pca/ciba/auth_req_id/v1' }
        raise TypeError, 'canonicalize: unsupported type undefined' unless step_up.key?('id') # stepUp: undefined

        d['stepUp'] = step_up['id']
        auth_req_id = AtlasPca.hash_canonical(d)
      end
      # the reference tests the coerced string against the pattern; only a String (or Array) has a .length to bound
      id_len = if auth_req_id.is_a?(String) || auth_req_id.is_a?(Array) then auth_req_id.length end
      unless rx?(AUTH_REQ_ID, Js.string(auth_req_id)) && (id_len.nil? || (id_len >= MIN_AUTH_REQ_ID_LEN && id_len <= 1024))
        raise ArgumentError, 'ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)'
      end

      bm = o['binding_message'].is_a?(Hash) ? o['binding_message'] : {}
      if bm.key?('max_chars') && !(Js.num?(bm['max_chars']) && Js.safe_integer?(bm['max_chars']) && bm['max_chars'] >= 1)
        raise ArgumentError, 'ciba: bindingMessage.maxChars must be a positive integer'
      end

      max_chars = bm.key?('max_chars') ? int_of(bm['max_chars']) : 50
      # The binding message is advisory; the canonical render is what the approval commits to. A word-string of H(R) rides in it
      # so a person can see the push and the original screen are the same transaction.
      words = nil
      if step_up.key?('render') || step_up.key?('renderDigest')
        if !step_up.key?('render') || !step_up.key?('renderDigest') ||
           AtlasPca.approval_render_digest(step_up['render']) != step_up['renderDigest']
          raise ArgumentError, 'ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else'
        end

        words = AtlasPca.binding_words(step_up['renderDigest'])
      end
      reserve = words.nil? ? 0 : words.length + 14
      token_only = bm['token_only'] == true
      msg = if token_only
              compact_binding_message(step_up, max_chars - reserve)
            else
              binding_message(step_up, acts_for, bm.key?('max_chars') ? max_chars - reserve : nil)
            end
      msg = token_only ? "#{msg}-match-#{words}" : "#{msg} [match code #{words}]" unless words.nil?
      req = { 'auth_req_id' => auth_req_id, 'binding_message' => msg, 'scope' => scope, 'requested_expiry' => int_of(expiry),
              'interval' => int_of(interval) }
      req['login_hint'] = o['login_hint'] if o.key?('login_hint')
      req['stepUpId'] = step_up['id'] if step_up.key?('id')
      req['tier'] = step_up['tier'] if step_up.key?('tier')
      if step_up.key?('render') && step_up.key?('renderDigest')
        req['authorization_details'] = [{ 'type' => 'pca_approval', 'render' => step_up['render'], 'render_digest' => step_up['renderDigest'] }]
        req['render_digest'] = step_up['renderDigest']
      end
      req
    end

    # ---- gating and the budget effect ---------------------------------------------------------------------------------------

    # Only a tier-3 step-up (human required) goes through CIBA; tier 2 is the guardian's auto-cosign; auto / deny never interrupt.
    def requires_ciba(review)
      raise TypeError, "Cannot read properties of null (reading 'kind')" if review.nil?
      return false unless review.is_a?(Hash) && review['kind'] == 'step_up'

      req = review['request']
      raise TypeError, "Cannot read properties of #{review.key?('request') ? 'null' : 'undefined'} (reading 'tier')" if req.nil?

      req.is_a?(Hash) && Js.num?(req['tier']) && req['tier'] == 3
    end

    # Fold a settled decision into the trust budget: approve recharges (partial rho, or full with opts['full']), deny leaves it
    # unchanged. Budget level only: the cryptographic cosign that authorises a tier-3 action is a FROST signature.
    def ciba_decision_to_cosign(decision, budget, policy, now, opts = nil)
      return { 'budget' => budget, 'cosigned' => false } unless decision == 'approve'

      full = opts.is_a?(Hash) && Js.truthy?(opts['full'])
      b = full ? Risk.recharge_full(budget, policy['bMax'], now) : Risk.recharge(budget, policy['rho'], policy['bMax'], now)
      { 'budget' => b, 'cosigned' => true }
    end

    # ---- brokers ------------------------------------------------------------------------------------------------------------
    def deep_copy(v)
      case v
      when Hash then v.to_h { |k, x| [k, deep_copy(x)] }
      when Array then v.map { |x| deep_copy(x) }
      when String then v.dup
      else v
      end
    end

    def clock_of(opts) = opts['now'] || -> { (Time.now.to_f * 1000).floor }
    def random_id = SecureRandom.urlsafe_base64(20)
    def req_opts(o) = o.is_a?(Hash) ? o : {}

    # In-memory broker (single process, test double): start / poll / token / resolve / get with POLL and PING (on_complete).
    class MemoryBroker
      def initialize(opts)
        @clock = Ciba.clock_of(opts)
        @on_complete = opts['on_complete']
        @sessions = {}
        @live = {}
      end

      def start(step_up, opts = nil)
        raise TypeError, "Cannot read properties of #{step_up.nil? ? 'null' : 'undefined'} (reading 'id')" unless step_up.is_a?(Hash)

        now = @clock.call
        existing = @sessions[@live[step_up['id']]] if @live.key?(step_up['id'])
        return existing['request'] if existing && %w[pending approved].include?(status(existing, now))

        request = Ciba.to_ciba_auth_request(step_up, Ciba.req_opts(opts).merge('auth_req_id' => Ciba.random_id))
        @sessions[request['auth_req_id']] = { 'request' => request, 'createdAt' => now,
                                              'expiresAt' => now + (request['requested_expiry'] * 1000), 'interval' => request['interval'] }
        @live[step_up['id']] = request['auth_req_id']
        request
      end

      def poll(id)
        s = @sessions[id] or raise "ciba: unknown auth_req_id #{Js.string(id)}"
        { 'status' => status(s, @clock.call) }
      end

      def token(id)
        s = @sessions[id]
        return { 'ok' => false, 'error' => 'invalid_grant', 'interval' => DEFAULT_INTERVAL_SEC } if s.nil?

        now = @clock.call
        return { 'ok' => false, 'error' => 'invalid_grant', 'interval' => s['interval'] } if s['consumed']

        too_soon = s.key?('lastPollAt') && now - s['lastPollAt'] < s['interval'] * 1000
        s['lastPollAt'] = now
        if too_soon
          s['interval'] += 5
          return { 'ok' => false, 'error' => 'slow_down', 'interval' => s['interval'] }
        end
        case status(s, now)
        when 'pending' then return { 'ok' => false, 'error' => 'authorization_pending', 'interval' => s['interval'] }
        when 'denied' then return { 'ok' => false, 'error' => 'access_denied', 'interval' => s['interval'] }
        when 'expired' then return { 'ok' => false, 'error' => 'expired_token', 'interval' => s['interval'] }
        end
        s['consumed'] = true
        { 'ok' => true, 'session' => snapshot(s, now) }
      end

      def resolve(id, decision, by)
        s = @sessions[id] or raise "ciba: unknown auth_req_id #{Js.string(id)}"
        now = @clock.call
        cur = status(s, now)
        raise "ciba: cannot resolve #{Js.string(id)} \u2014 already #{cur}" unless cur == 'pending'

        s['decision'] = decision
        s['decidedBy'] = by unless by.nil?
        s['decidedAt'] = now
        snap = snapshot(s, now)
        @on_complete&.call(snap)
        snap
      end

      def get(id)
        s = @sessions[id]
        s && snapshot(s, @clock.call)
      end

      private

      def status(s, now)
        return 'approved' if s['decision'] == 'approve'
        return 'denied' if s['decision'] == 'deny'

        Ciba.finite?(now) && Ciba.finite?(s['expiresAt']) && now < s['expiresAt'] ? 'pending' : 'expired'
      end

      def snapshot(s, now)
        out = { 'auth_req_id' => s['request']['auth_req_id'], 'request' => s['request'], 'status' => status(s, now),
                'createdAt' => s['createdAt'], 'expiresAt' => s['expiresAt'] }
        out['decidedBy'] = s['decidedBy'] if s.key?('decidedBy')
        out['decidedAt'] = s['decidedAt'] if s.key?('decidedAt')
        out
      end
    end

    # Durable broker over an ApprovalStore (#get(key) -> {'version','value'} | nil, #cas(key, expected_version, value) -> bool):
    # a restart or a second process cannot lose, double-apply or replay a decision. An approval stays redeemable for
    # decision_ttl_sec (default 300) after the decision, then reads expired.
    class DurableBroker
      def initialize(opts)
        store = opts.is_a?(Hash) ? opts['store'] : nil
        unless store.respond_to?(:get) && store.respond_to?(:cas)
          raise TypeError, 'createDurableCibaBroker: `store` is required'
        end

        ttl = opts['decision_ttl_sec'].nil? ? 300 : opts['decision_ttl_sec']
        unless Ciba.finite?(ttl) && ttl.positive?
          raise TypeError, 'createDurableCibaBroker: decisionTtlSec must be a positive number'
        end

        @store = store
        @clock = Ciba.clock_of(opts)
        @ttl_ms = ttl * 1000
        @on_complete = opts['on_complete']
      end

      def start(step_up, opts = nil)
        raise TypeError, "Cannot read properties of #{step_up.nil? ? 'null' : 'undefined'} (reading 'id')" unless step_up.is_a?(Hash)

        live_key = "s:#{Js.string(step_up['id'])}"
        MAX_CAS_TRIES.times do
          now = @clock.call
          idx = @store.get(live_key)
          unless idx.nil?
            ex = load(Js.string(idx['value']))
            if ex && %w[pending approved].include?(status(ex[:rec], now)) && !Js.truthy?(ex[:rec]['consumed'])
              return ex[:rec]['request']
            end
          end
          request = Ciba.to_ciba_auth_request(step_up, Ciba.req_opts(opts).merge('auth_req_id' => Ciba.random_id))
          rec = { 'request' => request, 'createdAt' => now, 'expiresAt' => now + (request['requested_expiry'] * 1000),
                  'interval' => request['interval'] }
          next unless @store.cas("a:#{request['auth_req_id']}", 0, rec)
          return request if @store.cas(live_key, idx.nil? ? 0 : idx['version'], request['auth_req_id'])
        end
        raise 'ciba: approval store contention, gave up'
      end

      def poll(id)
        c = load(id) or raise "ciba: unknown auth_req_id #{Js.string(id)}"
        { 'status' => status(c[:rec], @clock.call) }
      end

      def token(id)
        mutate(id) do |r, now|
          next [nil, { 'ok' => false, 'error' => 'invalid_grant', 'interval' => DEFAULT_INTERVAL_SEC }] if r.nil?
          next [nil, { 'ok' => false, 'error' => 'invalid_grant', 'interval' => r['interval'] }] if Js.truthy?(r['consumed'])

          too_soon = Ciba.finite?(r['lastPollAt']) && now - r['lastPollAt'] < r['interval'] * 1000
          r['lastPollAt'] = now
          if too_soon
            r['interval'] += 5
            next [r, { 'ok' => false, 'error' => 'slow_down', 'interval' => r['interval'] }]
          end
          err = { 'pending' => 'authorization_pending', 'denied' => 'access_denied', 'expired' => 'expired_token' }[status(r, now)]
          next [r, { 'ok' => false, 'error' => err, 'interval' => r['interval'] }] if err

          r['consumed'] = true # single use: a replayed approval gets invalid_grant
          [r, { 'ok' => true, 'session' => snap(r, now) }]
        end
      end

      def resolve(id, decision, by)
        raise 'ciba: decision must be "approve" or "deny"' unless %w[approve deny].include?(decision)
        raise 'ciba: `by` (the authenticated decider) is required' unless by.is_a?(String) && !by.empty?

        session = mutate(id) do |r, now|
          raise "ciba: unknown auth_req_id #{Js.string(id)}" if r.nil?

          cur = status(r, now)
          raise "ciba: cannot resolve #{Js.string(id)} \u2014 already #{cur}" unless cur == 'pending'

          r['decision'] = decision
          r['decidedBy'] = by
          r['decidedAt'] = now
          [r, snap(r, now)]
        end
        begin
          @on_complete&.call(session)
        rescue StandardError
          nil # the decision is already recorded; a failing notifier must not undo or hide it
        end
        session
      end

      def get(id)
        c = load(id)
        c && snap(c[:rec], @clock.call)
      end

      private

      def as_rec(v)
        ok = v.is_a?(Hash) && v['request'].is_a?(Hash) && v['request']['auth_req_id'].is_a?(String) &&
             Ciba.finite?(v['createdAt']) && Ciba.finite?(v['expiresAt']) && Ciba.finite?(v['interval'])
        raise 'ciba: stored approval record is malformed' unless ok

        v
      end

      def load(id)
        v = @store.get("a:#{Js.string(id)}")
        v.nil? ? nil : { rec: as_rec(v['value']), version: v['version'] }
      end

      # Read-modify-write with CAS retry; the block returns [next_record_or_nil, result].
      def mutate(id)
        MAX_CAS_TRIES.times do
          cur = load(id)
          nxt, out = yield(cur && Ciba.deep_copy(cur[:rec]), @clock.call)
          return out if nxt.nil?
          return out if @store.cas("a:#{Js.string(id)}", cur.nil? ? 0 : cur[:version], nxt)
        end
        raise 'ciba: approval store contention, gave up'
      end

      def status(r, now)
        return 'denied' if r['decision'] == 'deny'
        # a record without a decision time is treated as stale (fail closed)
        return Ciba.finite?(now) && Ciba.finite?(r['decidedAt']) && now < r['decidedAt'] + @ttl_ms ? 'approved' : 'expired' if r['decision'] == 'approve'

        Ciba.finite?(now) && Ciba.finite?(r['expiresAt']) && now < r['expiresAt'] ? 'pending' : 'expired'
      end

      def snap(r, now)
        out = { 'auth_req_id' => r['request']['auth_req_id'], 'request' => r['request'], 'status' => status(r, now),
                'createdAt' => r['createdAt'], 'expiresAt' => r['expiresAt'] }
        out['decidedBy'] = r['decidedBy'] if r.key?('decidedBy')
        out['decidedAt'] = r['decidedAt'] if r.key?('decidedAt')
        out
      end
    end

    # opts: now (callable -> epoch ms), on_complete (callable(session), PING/PUSH; omit for POLL).
    def create_ciba_broker(opts = {}) = MemoryBroker.new(opts || {})

    # opts: store (REQUIRED), now, decision_ttl_sec, on_complete (a raise does not undo the decision).
    def create_durable_ciba_broker(opts) = DurableBroker.new(opts)

    # ---- stores -------------------------------------------------------------------------------------------------------------

    # Single-process test double. Not durable.
    class MemoryApprovalStore
      def initialize
        @m = {}
        @lock = Mutex.new
      end

      def get(key)
        @lock.synchronize do
          v = @m[key]
          v && { 'version' => v['version'], 'value' => Ciba.deep_copy(v['value']) }
        end
      end

      def cas(key, expected, value)
        @lock.synchronize do
          return false unless (@m[key] ? @m[key]['version'] : 0) == expected

          @m[key] = { 'version' => expected + 1, 'value' => Ciba.deep_copy(value) }
          true
        end
      end
    end

    # One JSON file rewritten atomically (temp file + rename); correct for ONE process at a time.
    class FileApprovalStore
      def initialize(path)
        @path = path
        @lock = Mutex.new # serialises threads; several processes need a database store
      end

      def get(key) = @lock.synchronize { load[key] }

      def cas(key, expected, value)
        @lock.synchronize do
          all = load
          cur = all[key].is_a?(Hash) && !all[key]['version'].nil? ? all[key]['version'] : 0
          return false unless cur == expected

          all[key] = { 'version' => expected + 1, 'value' => value }
          tmp = "#{@path}.#{Process.pid}.tmp"
          AtlasPca::PrivateFile.open(tmp, File::WRONLY | File::CREAT | File::TRUNC) { |f| f.write(Js.json(all)) }
          File.rename(tmp, @path)
          true
        end
      end

      private

      def load
        return {} unless File.exist?(@path)

        parsed = Js.parse(File.read(@path, encoding: 'UTF-8')) # a corrupt file raises: fail closed
        raise 'ciba: approval store file is corrupt' unless parsed.is_a?(Hash)

        parsed
      end
    end

    # A versioned ApprovalStore over a DurableKv (#get(key) -> String | nil, #put_if_equals(key, expected_or_nil, next) -> bool,
    # atomic across every process and durable before it returns). Each key holds {version, value} as JSON.
    class KvApprovalStore
      def initialize(kv)
        unless kv.respond_to?(:get) && kv.respond_to?(:put_if_equals)
          raise TypeError, 'createKvApprovalStore: `kv` with get and putIfEquals is required'
        end

        @kv = kv
      end

      def get(key)
        raw = @kv.get(key)
        raw.nil? ? nil : decode(raw)
      end

      def cas(key, expected, value)
        raw = @kv.get(key)
        current = raw.nil? ? 0 : decode(raw)['version']
        return false unless current == expected

        @kv.put_if_equals(key, raw, Js.json({ 'version' => expected + 1, 'value' => value })) == true
      end

      private

      def decode(raw)
        r = begin
          Js.parse(raw)
        rescue StandardError
          raise ApprovalStoreError.new('corrupt_record', 'ciba: stored approval record is not valid JSON')
        end
        v = r.is_a?(Hash) ? r['version'] : nil
        unless r.is_a?(Hash) && (v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor)) && v >= 1 && r.key?('value')
          raise ApprovalStoreError.new('corrupt_record', 'ciba: stored approval record has no valid version')
        end

        { 'version' => v.to_i, 'value' => r['value'] }
      end
    end

    # Single-process DurableKv for tests. Not durable.
    class MemoryKv
      def initialize
        @m = {}
        @lock = Mutex.new
      end

      def get(key) = @lock.synchronize { @m[key] }

      def put_if_equals(key, expected, nxt)
        @lock.synchronize do
          return false unless @m[key] == expected

          @m[key] = nxt
          true
        end
      end
    end

    # A DurableKv on a directory, safe for several processes on ONE host: one file per (hashed) key, a per-key lock file taken
    # by exclusive create, compare, fsync'd temp file renamed over the key. A lock left by a dead process makes every later swap
    # on that key raise lock_timeout (fail closed) until an operator removes the .lock file.
    class DirectoryKv
      def initialize(dir, lock_timeout_ms: 5000)
        raise TypeError, 'createDirectoryKv: lockTimeoutMs must be a positive number' unless Ciba.finite?(lock_timeout_ms) && lock_timeout_ms.positive?

        @dir = dir
        @timeout = lock_timeout_ms
        AtlasPca::PrivateFile.mkdir_p(dir)
      end

      def get(key)
        f = file_of(key)
        File.exist?(f) ? File.read(f, encoding: 'UTF-8') : nil
      end

      def put_if_equals(key, expected, nxt)
        f = file_of(key)
        lock = "#{f}.lock"
        deadline = now_ms + @timeout
        fd = nil
        while fd.nil?
          begin
            fd = AtlasPca::PrivateFile.open(lock, File::WRONLY | File::CREAT | File::EXCL)
          rescue Errno::EEXIST
            raise ApprovalStoreError.new('lock_timeout', 'ciba: could not take the store lock in time') if now_ms >= deadline

            sleep 0.002
          end
        end
        begin
          current = File.exist?(f) ? File.read(f, encoding: 'UTF-8') : nil
          return false unless current == expected

          tmp = "#{f}.#{Process.pid}.tmp"
          AtlasPca::PrivateFile.open(tmp, File::WRONLY | File::CREAT | File::TRUNC) do |t|
            t.write(nxt)
            t.fsync # durable before the rename publishes it
          end
          File.rename(tmp, f)
          true
        ensure
          fd.close
          File.unlink(lock)
        end
      end

      private

      def now_ms = Process.clock_gettime(Process::CLOCK_MONOTONIC, :millisecond)

      # the key is hashed into the file name, so no key can escape the directory
      def file_of(key)
        raise ApprovalStoreError.new('bad_key', 'ciba: store key must be a non-empty string') unless key.is_a?(String) && !key.empty?

        File.join(@dir, Digest::SHA256.hexdigest(Js.utf8(key)))
      end
    end

    def create_memory_approval_store = MemoryApprovalStore.new
    def create_file_approval_store(path) = FileApprovalStore.new(path)
    def create_kv_approval_store(kv) = KvApprovalStore.new(kv)
    def create_memory_kv = MemoryKv.new
    def create_directory_kv(dir, lock_timeout_ms: 5000) = DirectoryKv.new(dir, lock_timeout_ms: lock_timeout_ms)

    # ---- the OP client (synchronous) ----------------------------------------------------------------------------------------

    # A fresh client_notification_token (CIBA Core 7.1: at least 128 bits, at most 1024 characters).
    def new_client_notification_token = SecureRandom.urlsafe_base64(32)

    # application/x-www-form-urlencoded (URLSearchParams#toString): * - . _ and alphanumerics kept, space as +.
    def form_enc(s) = s.scrub("\u{FFFD}").b.gsub(/[^*\-._0-9A-Za-z ]/n) { |c| format('%%%02X', c.ord) }.tr(' ', '+')
    def form(pairs) = pairs.map { |k, v| "#{form_enc(k)}=#{form_enc(v)}" }.join('&')

    def net_http_fetch(url, init)
      require 'net/http'
      u = URI(url)
      t = init['timeout_ms'] / 1000.0
      Net::HTTP.start(u.host, u.port, use_ssl: u.scheme == 'https', open_timeout: t, read_timeout: t, write_timeout: t) do |h|
        req = Net::HTTP::Post.new(u)
        init['headers'].each { |k, v| req[k] = v }
        req.body = init['body']
        r = h.request(req)
        { 'status' => r.code.to_i, 'body' => r.body.to_s }
      end
    end

    def check_endpoint(name, value, allow_insecure)
      u = WhatwgUrl.parse(Js.string(value))
      raise ArgumentError, "ciba: #{name} is not a valid URL" if u.nil?
      return if u['scheme'] == 'https' || (u['scheme'] == 'http' && allow_insecure)

      raise ArgumentError, "ciba: #{name} must be an https:// URL (set allowInsecureHttp only for a local test provider)"
    end

    def provider_error(status, body)
      error = body['error'].is_a?(String) ? body['error'] : 'invalid_response'
      desc = body['error_description'].is_a?(String) ? body['error_description'] : nil
      CibaProviderError.new(status, error, desc)
    end

    def read_json(status, text)
      parsed = begin
        Js.parse(text.to_s)
      rescue StandardError
        raise CibaProviderError.new(status, 'invalid_response', 'the provider reply was not JSON', true)
      end
      raise CibaProviderError.new(status, 'invalid_response', 'the provider reply was not a JSON object') unless parsed.is_a?(Hash)

      parsed
    end

    def positive_int(value, name, status)
      unless Js.num?(value) && Js.safe_integer?(value) && value.positive?
        raise CibaProviderError.new(status, 'invalid_response', "#{name} must be a positive integer")
      end

      int_of(value)
    end

    def sec(ms) = (ms % 1000).zero? ? ms / 1000 : ms / 1000.0

    # cfg: backchannel_authentication_endpoint, token_endpoint, client_id, client_secret (REQUIRED); fetch (callable(url, init)
    # with init {'method','headers','body','timeout_ms'} -> {'status','body'}; default Net::HTTP), sleep (callable(ms)), now,
    # timeout_ms (default 30000), allow_insecure_http (local test providers only). Authenticates with client_secret_basic. The
    # returned tokens are the OP's response, unverified: verify an ID token with your own JOSE library before relying on it.
    class Client
      def initialize(cfg)
        @fetch = cfg['fetch'] || Ciba.method(:net_http_fetch)
        @clock = Ciba.clock_of(cfg)
        @sleep = cfg['sleep'] || ->(ms) { Kernel.sleep(ms / 1000.0) }
        @timeout = cfg['timeout_ms'].nil? ? DEFAULT_TIMEOUT_MS : cfg['timeout_ms']
        raise ArgumentError, 'ciba: timeoutMs must be a positive number' unless Ciba.finite?(@timeout) && @timeout.positive?

        insecure = cfg['allow_insecure_http'] == true
        Ciba.check_endpoint('backchannelAuthenticationEndpoint', cfg['backchannel_authentication_endpoint'], insecure)
        Ciba.check_endpoint('tokenEndpoint', cfg['token_endpoint'], insecure)
        @bc = cfg['backchannel_authentication_endpoint']
        @token_endpoint = cfg['token_endpoint']
        cred = "#{Js.encode_uri_component(Js.string(cfg['client_id']))}:#{Js.encode_uri_component(Js.string(cfg['client_secret']))}"
        @basic = "Basic #{Base64.strict_encode64(AtlasPca::Js.utf8(cred))}"
      end

      attr_reader :clock, :token_endpoint

      # One POST; a transport failure is a retryable network_error. Returns [status, body_text].
      def post(url, pairs)
        init = { 'method' => 'POST', 'headers' => { 'authorization' => @basic, 'content-type' => 'application/x-www-form-urlencoded',
                                                     'accept' => 'application/json' },
                 'body' => Ciba.form(pairs), 'timeout_ms' => @timeout }
        res = begin
          @fetch.call(url, init)
        rescue StandardError => e
          raise CibaProviderError.new(0, 'network_error', e.message, true)
        end
        [res['status'], res['body'].to_s]
      end

      def pause(ms) = @sleep.call(ms)

      def initiate(step_up, opts = nil)
        o = opts.is_a?(Hash) ? opts : {}
        hints = %w[login_hint login_hint_token id_token_hint].count { |k| o.key?(k) }
        raise ArgumentError, 'ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)' unless hints == 1

        delivery = o['delivery'].nil? ? 'poll' : o['delivery']
        token = o['client_notification_token']
        if o.key?('client_notification_token') &&
           !(token.is_a?(String) && Js.len16(token).between?(MIN_NOTIFICATION_TOKEN_CHARS, MAX_NOTIFICATION_TOKEN_CHARS) && Ciba.rx?(NOTIFICATION_TOKEN, token))
          raise ArgumentError, "ciba: clientNotificationToken must be #{MIN_NOTIFICATION_TOKEN_CHARS}..#{MAX_NOTIFICATION_TOKEN_CHARS} " \
                               'printable characters (>= 128 bits, CIBA Core 7.1)'
        end
        notification = delivery == 'ping' ? (token.nil? ? Ciba.new_client_notification_token : token) : nil
        request = Ciba.to_ciba_auth_request(step_up, o)
        pairs = [['scope', request['scope']], ['binding_message', request['binding_message']], ['requested_expiry', Js.string(request['requested_expiry'])]]
        { 'login_hint' => 'login_hint', 'login_hint_token' => 'login_hint_token', 'id_token_hint' => 'id_token_hint',
          'acr_values' => 'acr_values', 'user_code' => 'user_code' }.each { |k, f| pairs << [f, Js.string(o[k])] if o.key?(k) }
        pairs << ['client_notification_token', notification] unless notification.nil?
        status, text = post(@bc, pairs)
        body = Ciba.read_json(status, text)
        raise Ciba.provider_error(status, body) unless (200..299).cover?(status)

        id = body['auth_req_id']
        raise CibaProviderError.new(status, 'invalid_response', 'auth_req_id missing') unless id.is_a?(String) && !id.empty?

        expires = Ciba.positive_int(body['expires_in'], 'expires_in', status)
        # CIBA Core 7.3: interval is optional and defaults to 5 seconds
        interval = body.key?('interval') ? Ciba.positive_int(body['interval'], 'interval', status) : 5
        flow = { 'authReqId' => id, 'expiresInSec' => expires, 'intervalSec' => interval, 'startedAt' => @clock.call, 'delivery' => delivery }
        flow['clientNotificationToken'] = notification unless notification.nil?
        flow['request'] = request
        flow
      end

      def poller(flow) = Poller.new(self, flow)
    end

    # Poll discipline (CIBA Core 7.3 / 11): never faster than the interval, +5 s on every slow_down, stop at expires_in; a
    # settled answer is cached so a settled flow is never re-sent (an approved auth_req_id is single-use at real OPs).
    class Poller
      def initialize(client, flow)
        @c = client
        @flow = flow
        @interval_ms = flow['intervalSec'] * 1000
        @next_at = flow['startedAt'] + @interval_ms
        @deadline = flow['startedAt'] + (flow['expiresInSec'] * 1000)
        @settled = nil
        @failures = 0
      end

      def interval_sec = Ciba.sec(@interval_ms)

      # A PING arrived: the next poll may go out immediately.
      def notify
        @next_at = @c.clock.call
        nil
      end

      # Sleep until the interval allows it, then ask the token endpoint once.
      def poll
        return @settled if @settled

        wait = @next_at - @c.clock.call
        @c.pause(wait) if wait.positive?
        return @settled = { 'status' => 'expired' } if @c.clock.call >= @deadline

        begin
          status, text = @c.post(@c.token_endpoint, [['grant_type', CIBA_GRANT], ['auth_req_id', @flow['authReqId']]])
          raise CibaProviderError.new(status, 'server_error', 'the provider answered with a server error', true) if status >= 500

          body = Ciba.read_json(status, text)
        rescue CibaProviderError => e
          backoff if e.retryable
          raise
        end
        @failures = 0
        @next_at = @c.clock.call + @interval_ms
        if (200..299).cover?(status)
          unless body['access_token'].is_a?(String) && body['token_type'].is_a?(String)
            raise CibaProviderError.new(status, 'invalid_response', 'token response lacks access_token / token_type')
          end

          return @settled = { 'status' => 'approved', 'tokens' => body }
        end
        err = Ciba.provider_error(status, body)
        case err.error
        when 'authorization_pending' then { 'status' => 'pending', 'intervalSec' => interval_sec }
        when 'slow_down'
          @interval_ms += SLOW_DOWN_STEP_SEC * 1000
          @next_at = @c.clock.call + @interval_ms
          { 'status' => 'pending', 'intervalSec' => interval_sec }
        when 'access_denied' then @settled = { 'status' => 'denied', 'error' => err.error }
        when 'expired_token' then @settled = { 'status' => 'expired' }
        else raise err
        end
      end

      # Poll until the flow settles; up to MAX_CONSECUTIVE_TRANSIENT retryable failures in a row are absorbed.
      def wait
        transient = 0
        loop do
          r = poll
          transient = 0
          return r unless r['status'] == 'pending'
        rescue CibaProviderError => e
          raise if !e.retryable || (transient += 1) >= MAX_CONSECUTIVE_TRANSIENT
        end
      end

      private

      def backoff
        @failures += 1
        @next_at = @c.clock.call + [MAX_BACKOFF_MS, @interval_ms * (2**[@failures, 6].min)].min
      end
    end

    def create_ciba_client(cfg) = Client.new(cfg)

    # Validate a PING callback (CIBA Core 10.2): Authorization: Bearer <client_notification_token> (constant-time compare) and a
    # JSON body {auth_req_id} of this flow. Returns the auth_req_id; raises otherwise. It carries no decision: notify + poll.
    def verify_ping_callback(input, flow)
      tok = flow.is_a?(Hash) ? flow['clientNotificationToken'] : nil
      raise ArgumentError, 'ciba: flow was not started in ping mode' if tok.nil? && !(flow.is_a?(Hash) && flow.key?('clientNotificationToken'))
      raise TypeError, 'ciba: ping callback input must be an object' unless input.is_a?(Hash)

      auth = input['authorization']
      m = BEARER.match((auth.nil? ? '' : Js.string(auth)).scrub("\u{FFFD}"))
      raise ArgumentError, 'ciba: ping callback lacks a bearer token' if m.nil?

      # a non-string token reaches the hash update, which Node refuses
      raise CodedError.new('ERR_INVALID_ARG_TYPE', 'The "data" argument must be of type string or an instance of Buffer, TypedArray, or DataView') unless tok.is_a?(String)

      d = ->(v) { Digest::SHA256.digest(Js.utf8(v)) }
      unless OpenSSL.fixed_length_secure_compare(d.call(m[1]), d.call(tok))
        raise ArgumentError, 'ciba: ping callback bearer does not match the client_notification_token'
      end

      id = input['body'].is_a?(Hash) ? input['body']['auth_req_id'] : nil
      raise ArgumentError, 'ciba: ping callback auth_req_id does not match this flow' unless id.is_a?(String) && id == flow['authReqId']

      id
    end
  end
end
