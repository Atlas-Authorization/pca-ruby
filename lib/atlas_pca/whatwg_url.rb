# frozen_string_literal: true

require 'ipaddr'
require_relative 'ada_idna'

# The subset of the WHATWG URL parser the protocol bridges need (the reference runs on the platform URL class): scheme,
# serialized host[:port], pathname (dot segments resolved, percent-encoded as the standard does), search and origin.
# A non-ASCII host is mapped through Ada when ATLAS_PCA_LIBADA names a libada build (AdaIdna, opt-in); without it the host is refused.
module AtlasPca
  module WhatwgUrl
    SPECIAL = { 'ftp' => 21, 'file' => nil, 'http' => 80, 'https' => 443, 'ws' => 80, 'wss' => 443 }.freeze
    PATH_ENC = "\"<>`{}?"
    QUERY_ENC = "\"<>'"

    module_function

    def pct(s, extra, controls_only = false)
      s.each_char.map do |ch|
        o = ch.ord
        if o < 0x20 || o > 0x7e || (!controls_only && (o == 0x20 || extra.include?(ch)))
          ch.encode('UTF-8', invalid: :replace, undef: :replace, replace: "�").bytes.map { |b| format('%%%02X', b) }.join
        else
          ch
        end
      end.join
    end

    def pct_decode(s) = s.b.gsub(/%([0-9A-Fa-f]{2})/n) { Regexp.last_match(1).to_i(16).chr }

    def ipv4_number(part)
      return nil if part.empty?

      radix = 10
      if part.length >= 2 && part[0, 2].casecmp?('0x')
        part = part[2..]
        radix = 16
      elsif part.length >= 2 && part[0] == '0'
        part = part[1..]
        radix = 8
      end
      return 0 if part.empty?

      re = { 10 => /\A[0-9]+\z/, 16 => /\A[0-9a-fA-F]+\z/, 8 => /\A[0-7]+\z/ }[radix]
      part.match?(re) ? part.to_i(radix) : nil
    end

    def ends_in_number?(host)
      parts = host.split('.', -1)
      if parts[-1] == ''
        return false if parts.length == 1

        parts.pop
      end
      last = parts[-1]
      !last.empty? && (last.match?(/\A[0-9]+\z/) || !ipv4_number(last).nil?)
    end

    def parse_ipv4(host)
      parts = host.split('.', -1)
      parts.pop if parts[-1] == '' && parts.length > 1
      return nil if parts.length > 4

      nums = parts.map { |p| ipv4_number(p) }
      return nil if nums.any?(&:nil?)
      return nil if nums[0..-2].any? { |n| n > 255 } || nums[-1] >= 256**(5 - nums.length)

      v = nums[-1] + nums[0..-2].each_with_index.sum { |n, i| n * (256**(3 - i)) }
      [3, 2, 1, 0].map { |k| (v >> (8 * k)) & 255 }.join('.')
    end

    def serialize_ipv6(int)
      h = (0..7).map { |i| (int >> (16 * (7 - i))) & 0xffff }
      best = -1
      best_len = 1
      i = 0
      while i < 8
        if h[i].zero?
          j = i
          j += 1 while j < 8 && h[j].zero?
          if j - i > best_len
            best = i
            best_len = j - i
          end
          i = j
        else
          i += 1
        end
      end
      out = +''
      i = 0
      while i < 8
        if i == best
          out << (i.zero? ? '::' : ':')
          i += best_len
          next
        end
        out << h[i].to_s(16) << (i == 7 ? '' : ':')
        i += 1
      end
      "[#{out}]"
    end

    def parse_host(text, special)
      if text.start_with?('[')
        return nil if !text.end_with?(']') || text.include?('%')

        inner = text[1..-2]
        return nil unless inner.match?(/\A[0-9A-Fa-f:.]+\z/)

        begin
          ip = IPAddr.new(inner)
        rescue IPAddr::Error, ArgumentError
          return nil
        end
        return ip.ipv6? ? serialize_ipv6(ip.to_i) : nil
      end
      return(text.match?(/[\x00\t\n\r #\/<>?@\[\\\]^|]/) ? nil : pct(text, '', true)) unless special

      domain = pct_decode(text).force_encoding('UTF-8')
      return nil unless domain.valid_encoding?

      unless domain.ascii_only?
        # an IDN host maps through Ada (opt-in: ATLAS_PCA_LIBADA); without it, refused. The forbidden code points are judged BEFORE the
        # library sees the text (it would otherwise read `a/b` as the host `a`).
        return nil if !AdaIdna.available? || domain.match?(/[\x00-\x20#%\/:<>?@\[\\\]^|\x7f]/)

        domain = AdaIdna.domain_to_ascii(domain)
      end

      domain = domain.downcase
      return nil if domain.empty? || domain.match?(/[\x00-\x20#%\/:<>?@\[\\\]^|\x7f]/)
      return parse_ipv4(domain) if ends_in_number?(domain)

      domain
    end

    # {scheme, host, htu, pathname, origin?, search?} or nil when the platform URL class would refuse the text.
    def parse(str)
      return nil unless str.is_a?(String)

      s = str.encode('UTF-8', invalid: :replace, undef: :replace, replace: "�")
      s = s.sub(/\A[\x00-\x20]+/, '').sub(/[\x00-\x20]+\z/, '').delete("\t\n\r")
      m = s.match(/\A([A-Za-z][A-Za-z0-9+.\-]*):/)
      return nil if m.nil?

      scheme = m[1].downcase
      rest = s[m.end(0)..]
      special = SPECIAL.key?(scheme)
      frag = rest.index('#')
      rest = rest[0, frag] if frag
      q = rest.index('?')
      query = nil
      if q
        query = rest[(q + 1)..]
        rest = rest[0, q]
      end
      host = ''
      port = nil
      has_cred = false
      hostport = ''
      authority = nil
      if special && scheme != 'file'
        rest = rest.sub(%r{\A[/\\]+}, '')
        cut = rest.index(%r{[/\\]})
        authority, path = cut ? [rest[0, cut], rest[cut..]] : [rest, '']
        has_cred = authority.include?('@')
        hostport = authority.rpartition('@')[2]
      elsif rest.start_with?('//') || (scheme == 'file' && rest.match?(%r{\A[/\\]{2}}))
        body = rest[2..]
        cut = body.index(special ? %r{[/\\]} : %r{/})
        authority, path = cut ? [body[0, cut], body[cut..]] : [body, '']
        has_cred = authority.include?('@') && scheme != 'file'
        hostport = scheme == 'file' ? authority : authority.rpartition('@')[2]
      elsif special # file: without an authority
        authority = ''
        path = rest.sub(%r{\A[/\\]}, '/')
      else
        path = rest
      end
      unless authority.nil?
        if hostport.start_with?('[')
          e = hostport.index(']')
          return nil if e.nil?

          htxt = hostport[0..e]
          after = hostport[(e + 1)..]
          return nil if !after.empty? && !after.start_with?(':')

          ptxt = after.empty? ? nil : after[1..]
        else
          htxt, sep, ptxt = hostport.partition(':')
          ptxt = nil if sep.empty?
        end
        if !ptxt.nil? && !ptxt.empty?
          return nil unless ptxt.match?(/\A[0-9]+\z/) && ptxt.to_i <= 65_535

          port = SPECIAL[scheme] == ptxt.to_i ? nil : ptxt.to_i
        end
        return nil if special && scheme != 'file' && htxt.empty?
        return nil if has_cred && htxt.empty? && ptxt.nil? && hostport.empty?

        unless htxt.empty?
          ph = parse_host(htxt, special)
          return nil if ph.nil?

          host = scheme == 'file' && ph == 'localhost' ? '' : ph
        end
      end
      hp = host + (port.nil? ? '' : ":#{port}")
      pathname = if authority.nil?
                   pct(path, '', true) # an opaque path: only the control characters are encoded
                 else
                   segs = path.empty? ? [] : (special ? path.tr('\\', '/') : path).split('/', -1)[1..]
                   out = []
                   segs.each_with_index do |seg, i|
                     last = i == segs.length - 1
                     low = seg.downcase
                     if ['..', '.%2e', '%2e.', '%2e%2e'].include?(low)
                       out.pop
                       out << '' if last
                     elsif ['.', '%2e'].include?(low)
                       out << '' if last
                     else
                       out << pct(seg, PATH_ENC)
                     end
                   end
                   "/#{out.join('/')}"
                 end
      res = { 'scheme' => scheme, 'host' => hp, 'htu' => "#{scheme}://#{hp}#{pathname}", 'pathname' => pathname }
      if special
        res['origin'] = "#{scheme}://#{hp}"
        res['search'] = query.nil? || query.empty? ? '' : "?#{pct(query, QUERY_ENC)}"
      end
      res
    end
  end
end
