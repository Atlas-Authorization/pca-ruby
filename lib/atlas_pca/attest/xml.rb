# frozen_string_literal: true

# A strict XML subset parser and Inclusive Canonical XML (C14N 1.0, identical to C14N 1.1 for documents without `xml:*`
# attributes) for the NVIDIA RIM XMLDSig check. Pure standard library.
#
# Accepted: elements, attributes, text, CDATA, the five predefined entities and character references. Comments, processing
# instructions (including the XML declaration) and a DOCTYPE are PARSED but recorded as profile violations (the RIM profile
# rejects all of them); anything ill-formed raises XmlError.
require_relative 'common'

module AtlasPca
  module Attest
    class XmlError < StandardError; end

    module Xml
      XML_NS = 'http://www.w3.org/XML/1998/namespace'
      NAME_START = 'A-Za-z_:À-˿Ͱ-῿Ⰰ-퟿豈-﷏ﷰ-�'
      NAME_CHAR = 'A-Za-z0-9_:.\-·À-˿̀-῿Ⰰ-퟿豈-﷏ﷰ-�'
      NAME = Regexp.new("\\G[#{NAME_START}][#{NAME_CHAR}]*")
      WS = " \t\r\n"
      ENTITIES = { 'lt' => '<', 'gt' => '>', 'amp' => '&', 'quot' => '"', 'apos' => "'" }.freeze

      class Attr
        attr_accessor :qname, :prefix, :local, :ns, :value

        def initialize(qname, value)
          @qname = qname
          pre, sep, rest = qname.partition(':')
          if sep.empty?
            @prefix = ''
            @local = qname
          else
            @prefix = pre
            @local = rest
          end
          @ns = ''
          @value = value
        end
      end

      class Element
        attr_accessor :qname, :prefix, :local, :ns, :attrs, :decls, :scope, :children, :parent

        def initialize(qname, parent)
          @qname = qname
          pre, sep, rest = qname.partition(':')
          if sep.empty?
            @prefix = ''
            @local = qname
          else
            @prefix = pre
            @local = rest
          end
          @ns = ''
          @attrs = [] # without namespace declarations
          @decls = {} # declared on this element: prefix ('' = default) -> uri
          @scope = {} # in scope on this element (after its own declarations), without 'xml'
          @children = []
          @parent = parent
        end

        def get_attribute(qname)
          a = @attrs.find { |x| x.qname == qname }
          a.nil? ? '' : a.value
        end

        def element_children(ns = nil, local = nil)
          @children.select { |c| c.is_a?(Element) && (ns.nil? || c.ns == ns) && (local.nil? || c.local == local) }
        end

        def descendants(ns, local)
          out = []
          @children.each do |c|
            next unless c.is_a?(Element)

            out << c if c.ns == ns && c.local == local
            out.concat(c.descendants(ns, local))
          end
          out
        end

        def text_content = @children.map { |c| c.is_a?(String) ? c : c.text_content }.join
      end

      class Document
        attr_accessor :root, :violations

        def initialize
          @root = nil
          @violations = [] # in document order
        end
      end

      module_function

      def unescape(s, attr)
        return s if !s.include?('&') && !attr

        out = +''
        i = 0
        n = s.length
        while i < n
          ch = s[i]
          if ch == '&'
            j = s.index(';', i + 1)
            raise XmlError, 'unterminated entity reference' if j.nil?

            ref = s[(i + 1)...j]
            if ref.start_with?('#x', '#X')
              raise XmlError, 'bad character reference' unless ref[2..].match?(/\A[0-9a-fA-F]+\z/)

              out << [ref[2..].to_i(16)].pack('U')
            elsif ref.start_with?('#')
              raise XmlError, 'bad character reference' unless ref[1..].match?(/\A[0-9]+\z/)

              out << [ref[1..].to_i].pack('U')
            elsif ENTITIES.key?(ref)
              out << ENTITIES[ref]
            else
              raise XmlError, "unknown entity &#{ref};"
            end
            i = j + 1
            next
          end
          if attr && "\t\r\n".include?(ch)
            out << ' '
          elsif ch == '<' && attr
            raise XmlError, "'<' in an attribute value"
          else
            out << ch
          end
          i += 1
        end
        out
      end

      def sw?(s, pre, i) = s[i, pre.length] == pre

      def skip_ws(s, i)
        i += 1 while i < s.length && WS.include?(s[i])
        i
      end

      def strip_ws(s) = s.sub(/\A[ \t\r\n]+/, '').sub(/[ \t\r\n]+\z/, '')

      def parse_xml(text)
        doc = Document.new
        n = text.length
        i = 0
        stack = []
        while i < n
          if text[i] != '<'
            j = text.index('<', i)
            j = n if j.nil?
            chunk = text[i...j]
            if stack.empty?
              raise XmlError, 'text outside the root element' if strip_ws(chunk) != ''
            else
              stack[-1].children << unescape(chunk, false)
            end
            i = j
            next
          end
          if sw?(text, '<!--', i)
            j = text.index('-->', i + 4)
            raise XmlError, 'unterminated comment' if j.nil?

            doc.violations << 'XML comments are not permitted'
            i = j + 3
            next
          end
          if sw?(text, '<![CDATA[', i)
            j = text.index(']]>', i + 9)
            raise XmlError, 'bad CDATA section' if j.nil? || stack.empty?

            stack[-1].children << text[(i + 9)...j]
            i = j + 3
            next
          end
          if sw?(text, '<?', i)
            j = text.index('?>', i + 2)
            raise XmlError, 'unterminated processing instruction' if j.nil?

            doc.violations << 'XML processing instructions are not permitted'
            i = j + 2
            next
          end
          if sw?(text, '<!', i)
            depth = 0
            j = i + 2
            while j < n
              c = text[j]
              if c == '['
                depth += 1
              elsif c == ']'
                depth -= 1
              elsif c == '>' && depth <= 0
                break
              end
              j += 1
            end
            raise XmlError, 'unterminated declaration' if j >= n

            doc.violations << 'DTD / DOCTYPE is not permitted'
            i = j + 1
            next
          end
          if sw?(text, '</', i)
            m = NAME.match(text, i + 2)
            raise XmlError, 'bad end tag' if m.nil?

            j = skip_ws(text, m.end(0))
            raise XmlError, 'bad end tag' if j >= n || text[j] != '>'
            raise XmlError, "mismatched end tag </#{m[0]}>" if stack.empty? || stack[-1].qname != m[0]

            stack.pop
            i = j + 1
            next
          end
          # start tag
          m = NAME.match(text, i + 1)
          raise XmlError, 'bad start tag' if m.nil?

          parent = stack.empty? ? nil : stack[-1]
          raise XmlError, 'more than one root element' if parent.nil? && !doc.root.nil?

          el = Element.new(m[0], parent)
          j = m.end(0)
          raw_attrs = []
          k = nil
          loop do
            k = skip_ws(text, j)
            raise XmlError, 'unterminated start tag' if k >= n
            break if text[k] == '>' || sw?(text, '/>', k)
            raise XmlError, 'missing whitespace before an attribute' if k == j

            am = NAME.match(text, k)
            raise XmlError, 'bad attribute name' if am.nil?

            k = skip_ws(text, am.end(0))
            raise XmlError, 'attribute without a value' if k >= n || text[k] != '='

            k = skip_ws(text, k + 1)
            raise XmlError, 'unquoted attribute value' if k >= n || !"\"'".include?(text[k])

            q = text[k]
            e = text.index(q, k + 1)
            raise XmlError, 'unterminated attribute value' if e.nil?
            raise XmlError, "duplicate attribute #{am[0]}" if raw_attrs.any? { |a, _v| a == am[0] }

            raw_attrs << [am[0], unescape(text[(k + 1)...e], true)]
            j = e + 1
          end
          self_close = sw?(text, '/>', k)
          i = k + (self_close ? 2 : 1)
          scope = parent.nil? ? {} : parent.scope.dup
          raw_attrs.each do |qn, val|
            if qn == 'xmlns'
              el.decls[''] = val
            elsif qn.start_with?('xmlns:')
              raise XmlError, 'namespace prefix cannot be undeclared' if val == ''

              el.decls[qn[6..]] = val
            else
              el.attrs << Attr.new(qn, val)
            end
          end
          el.decls.each do |p, uri|
            if uri == '' && p == ''
              scope.delete('')
            else
              scope[p] = uri
            end
          end
          el.scope = scope
          if el.prefix != ''
            raise XmlError, "unbound namespace prefix #{el.prefix}" unless scope.key?(el.prefix)

            el.ns = scope[el.prefix]
          else
            el.ns = scope.fetch('', '')
          end
          el.attrs.each do |a|
            if a.prefix == 'xml'
              a.ns = XML_NS
            elsif a.prefix != ''
              raise XmlError, "unbound namespace prefix #{a.prefix}" unless scope.key?(a.prefix)

              a.ns = scope[a.prefix]
            end
            doc.violations << "xml:* attribute '#{a.qname}' is not permitted (C14N 1.1 profile)" if a.qname.downcase.start_with?('xml:')
          end
          if parent.nil?
            doc.root = el
          else
            parent.children << el
          end
          stack << el unless self_close
        end
        raise XmlError, "unclosed element <#{stack[-1].qname}>" unless stack.empty?
        raise XmlError, 'no root element' if doc.root.nil?

        doc
      end

      # ---- canonical XML

      def enc_text(s) = s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;').gsub("\r", '&#xD;')

      def enc_attr(s)
        s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('"', '&quot;').gsub("\t", '&#x9;').gsub("\n", '&#xA;').gsub("\r", '&#xD;')
      end

      # Inclusive C14N of the subtree at `el` (an apex: every in-scope namespace is declared on it). `skip` drops one
      # descendant (the enveloped Signature); `apex_scope` overrides the apex's in-scope namespaces.
      def canonicalize(el, skip = nil, apex_scope = nil)
        out = +''
        render(el, apex_scope.nil? ? el.scope : apex_scope, nil, skip, out)
        out
      end

      def render(el, scope, parent_out, skip, out)
        out << "<#{el.qname}"
        prev = parent_out || {}
        ns_out = []
        scope.each do |prefix, uri|
          if parent_out.nil? || prev[prefix] != uri
            ns_out << [prefix, uri]
          end
        end
        ns_out << ['', ''] if !parent_out.nil? && prev.key?('') && !scope.key?('') # xmlns="" undeclares the inherited default namespace
        ns_out.sort_by { |p, _| p.b }.each do |prefix, uri|
          out << (prefix == '' ? " xmlns=\"#{enc_attr(uri)}\"" : " xmlns:#{prefix}=\"#{enc_attr(uri)}\"")
        end
        el.attrs.sort_by { |a| [a.ns.b, a.local.b] }.each { |a| out << " #{a.qname}=\"#{enc_attr(a.value)}\"" }
        out << '>'
        el.children.each do |c|
          if c.is_a?(String)
            out << enc_text(c)
          elsif !c.equal?(skip)
            render(c, c.scope, scope.dup, skip, out)
          end
        end
        out << "</#{el.qname}>"
      end
    end
  end
end
