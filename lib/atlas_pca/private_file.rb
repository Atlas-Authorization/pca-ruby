# frozen_string_literal: true

# The one way the library creates a private (owner-only) file or directory. POSIX: mode 0600 / 0700 at creation. Windows: a
# mode does nothing there, so the file or directory is created with a protected DACL holding exactly one entry (full rights
# for the current user), set atomically by CreateFileW / CreateDirectoryW, never restricted afterwards. Win32 is reached
# through Fiddle (standard library). When the Win32 calls are unavailable the writers raise: never a world-readable file.
require 'rbconfig'
require 'fileutils'
require 'fiddle' if RbConfig::CONFIG['host_os'].match?(/mswin|mingw|cygwin/) # POSIX needs no Win32 calls

module AtlasPca
  module PrivateFile
    class Unavailable < StandardError; end

    module_function

    # not Gem.win_platform?: the library also loads with rubygems disabled
    WINDOWS = RbConfig::CONFIG['host_os'].match?(/mswin|mingw|cygwin/)

    def windows? = WINDOWS

    # Open (create) a private file. `flags` are File:: constants (WRONLY, RDWR, CREAT, EXCL, TRUNC, APPEND); EXCL keeps its
    # create-new meaning. With a block the file is closed after it, like File.open.
    def open(path, flags, binmode: false, &blk)
      return File.open(path, flags, 0o600, binmode: binmode, &blk) unless windows?

      io = Win.open_file(File.expand_path(path), flags, binmode)
      return io unless blk

      begin
        yield io
      ensure
        io.close unless io.closed?
      end
    end

    # write `data` to a new/truncated private file
    def write(path, data, binmode: true)
      self.open(path, File::WRONLY | File::CREAT | File::TRUNC, binmode: binmode) { |f| f.write(data) }
    end

    # Create the directory (and its missing parents; only the leaf is made owner-only) when it does not exist yet.
    def mkdir_p(path)
      path = File.expand_path(path)
      return FileUtils.mkdir_p(path, mode: 0o700) unless windows?
      return if File.directory?(path)

      FileUtils.mkdir_p(File.dirname(path))
      Win.create_directory(path)
    end

    # a private temporary directory (the equivalent of Dir.mktmpdir)
    def mktmpdir(prefix)
      require 'tmpdir'
      require 'securerandom'
      return block_given? ? Dir.mktmpdir(prefix) { |d| yield d } : Dir.mktmpdir(prefix) unless windows?

      dir = File.join(Dir.tmpdir, "#{prefix}#{SecureRandom.hex(8)}")
      Win.create_directory(File.expand_path(dir))
      return dir unless block_given?

      begin
        yield dir
      ensure
        FileUtils.remove_entry(dir) if File.exist?(dir)
      end
    end

    # What a path is restricted to: { mode: 0o600 } on POSIX, { sddl: 'D:P(A;;FA;;;<sid>)', sid: '<sid>' } on Windows.
    def restriction(path)
      return { mode: File.stat(path).mode & 0o777 } unless windows?

      { sddl: Win.dacl_sddl(File.expand_path(path)), sid: Win.current_sid }
    end

    # true when exactly one protected entry grants the current user alone (Windows) or the mode is `mode` (POSIX)
    def owner_only?(path, mode = 0o600)
      r = restriction(path)
      return r[:mode] == mode if r.key?(:mode)

      m = r[:sddl].match(/\AD:P\(A;;FA;;;([^()]+)\)\z/)
      # the read-back SDDL writes a well-known SID as an alias (the local administrator's -500 is "LA"): compare the SIDs, not the spellings
      !m.nil? && Win.normalize_sid(m[1]) == r[:sid]
    end

    if WINDOWS
    module Win
      GENERIC_READ = 0x80000000
      GENERIC_WRITE = 0x40000000
      FILE_APPEND_DATA = 0x4
      SHARE_ALL = 0x7
      CREATE_NEW = 1
      CREATE_ALWAYS = 2
      OPEN_EXISTING = 3
      OPEN_ALWAYS = 4
      TRUNCATE_EXISTING = 5
      FILE_ATTRIBUTE_NORMAL = 0x80
      INVALID_HANDLE = (2**(Fiddle::SIZEOF_VOIDP * 8)) - 1
      O_APPEND = 0x8
      O_BINARY = 0x8000
      O_TEXT = 0x4000
      PTR = Fiddle::TYPE_VOIDP
      INT = Fiddle::TYPE_INT
      UINT = Fiddle::TYPE_UINT
      STD = Fiddle.const_defined?(:Function) && Fiddle::Function.const_defined?(:STDCALL) ? Fiddle::Function::STDCALL : Fiddle::Function::DEFAULT

      module_function

      def fn(lib, name, args, ret)
        h = (@libs ||= {})[lib] ||= Fiddle.dlopen(lib)
        Fiddle::Function.new(h[name], args, ret, STD)
      rescue Fiddle::DLError => e
        raise Unavailable, "cannot create an owner-only file: #{lib}!#{name} is unavailable (#{e.message})"
      end

      # a NUL-terminated UTF-16LE copy of `s` as binary bytes (no string interpolation: that mixes the two encodings)
      def wide(s) = s.encode('UTF-16LE').b + "\0\0".b

      def read_wide(ptr)
        out = +''.b
        i = 0
        loop do
          c = ptr[i, 2]
          break if c == "\0\0"

          out << c
          i += 2
        end
        out.force_encoding('UTF-16LE').encode('UTF-8')
      end

      # the error code captured by Fiddle right after the last foreign call (a separate GetLastError call can see a reset value)
      def last_error = Fiddle.respond_to?(:win32_last_error) ? Fiddle.win32_last_error : fn('kernel32.dll', 'GetLastError', [], UINT).call

      def current_sid
        @current_sid ||= begin
          tok = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
          proc_h = fn('kernel32.dll', 'GetCurrentProcess', [], PTR).call
          raise Unavailable, "OpenProcessToken failed (#{last_error})" if fn('advapi32.dll', 'OpenProcessToken', [PTR, INT, PTR], INT).call(proc_h, 0x8, tok).zero?

          th = tok[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')
          need = Fiddle::Pointer.malloc(4, Fiddle::RUBY_FREE)
          gti = fn('advapi32.dll', 'GetTokenInformation', [PTR, INT, PTR, INT, PTR], INT)
          gti.call(th, 1, nil, 0, need)
          buf = Fiddle::Pointer.malloc(need[0, 4].unpack1('L'), Fiddle::RUBY_FREE)
          raise Unavailable, "GetTokenInformation failed (#{last_error})" if gti.call(th, 1, buf, buf.size, need).zero?

          sid_ptr = buf[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')
          out = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
          raise Unavailable, "ConvertSidToStringSidW failed (#{last_error})" if fn('advapi32.dll', 'ConvertSidToStringSidW', [PTR, PTR], INT).call(sid_ptr, out).zero?

          s = read_wide(Fiddle::Pointer.new(out[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')))
          fn('kernel32.dll', 'CloseHandle', [PTR], INT).call(th)
          s
        end
      end

      # SECURITY_ATTRIBUTES holding a protected DACL with one entry: full access for the current user
      def security_attributes
        psd = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
        conv = fn('advapi32.dll', 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [PTR, INT, PTR, PTR], INT)
        raise Unavailable, "cannot build the owner-only security descriptor (#{last_error})" if conv.call(wide("D:P(A;;FA;;;#{current_sid})"), 1, psd, nil).zero?

        sd = psd[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')
        sa = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP == 8 ? 24 : 12, Fiddle::RUBY_FREE)
        sa[0, sa.size] = Fiddle::SIZEOF_VOIDP == 8 ? [24, sd, 0].pack('LxxxxQL') + "\0\0\0\0" : [12, sd, 0].pack('LLL')
        [sa, sd]
      end

      def free_sd(sd) = fn('kernel32.dll', 'LocalFree', [PTR], PTR).call(sd)

      def open_file(path, flags, binmode)
        acc = flags & File::RDWR == File::RDWR ? GENERIC_READ | GENERIC_WRITE : (flags & File::WRONLY == File::WRONLY ? GENERIC_WRITE : GENERIC_READ)
        acc = (acc & ~GENERIC_WRITE) | FILE_APPEND_DATA if flags & File::APPEND != 0 && acc == GENERIC_WRITE
        creat = flags & File::CREAT != 0
        excl = flags & File::EXCL != 0
        trunc = flags & File::TRUNC != 0
        disp = if creat && excl then CREATE_NEW
               elsif creat && trunc then CREATE_ALWAYS
               elsif creat then OPEN_ALWAYS
               elsif trunc then TRUNCATE_EXISTING
               else OPEN_EXISTING
               end
        sa, sd = security_attributes
        h = err = nil
        begin
          h = fn('kernel32.dll', 'CreateFileW', [PTR, UINT, UINT, PTR, UINT, UINT, PTR], PTR).call(wide(path), acc, SHARE_ALL, sa, disp, FILE_ATTRIBUTE_NORMAL, 0).to_i
          err = last_error
        ensure
          free_sd(sd)
        end
        h &= INVALID_HANDLE # Fiddle may hand INVALID_HANDLE_VALUE back as -1: read the handle as unsigned before comparing
        if h == INVALID_HANDLE || h.zero?
          raise Errno::EEXIST, path if err == 80 || err == 183
          raise Errno::ENOENT, path if err == 2 || err == 3

          raise Errno::EACCES, "#{path} (Win32 error #{err})"
        end
        fd = open_osfhandle.call(h, (flags & File::APPEND != 0 ? O_APPEND : 0) | (binmode ? O_BINARY : O_TEXT))
        raise Unavailable, "_open_osfhandle failed for #{path}" if fd.negative?

        IO.for_fd(fd, acc == GENERIC_READ ? 'r' : (flags & File::APPEND != 0 ? 'a' : (acc & GENERIC_READ != 0 ? 'r+' : 'w')), binmode: binmode, autoclose: true)
      end

      # Ruby's IO uses the C runtime fd table of the running Ruby, so the handle is wrapped by the function Ruby itself exports
      # (rb_w32_open_osfhandle, found on the current process and then in the Ruby DLL); ucrtbase is only the last resort.
      def open_osfhandle
        @open_osfhandle ||= begin
          ruby_dll = RbConfig::CONFIG['LIBRUBY_SO'].to_s
          handles = [-> { Fiddle::Handle::DEFAULT }, -> { Fiddle::Handle.new(ruby_dll) }]
          addr = handles.lazy.map { |mk| mk.call['rb_w32_open_osfhandle'] rescue nil }.find(&:itself)
          addr ? Fiddle::Function.new(addr, [Fiddle::TYPE_INTPTR_T, INT], INT, STD) : fn('ucrtbase.dll', '_open_osfhandle', [Fiddle::TYPE_INTPTR_T, INT], INT)
        end
      end

      def create_directory(path)
        sa, sd = security_attributes
        ok = err = nil
        begin
          ok = fn('kernel32.dll', 'CreateDirectoryW', [PTR, PTR], INT).call(wide(path), sa)
          err = last_error
        ensure
          free_sd(sd)
        end
        return unless ok.zero?

        raise Errno::EEXIST, path if err == 183

        raise Errno::EACCES, "#{path} (Win32 error #{err})"
      end

      # the canonical string form of a SID given as a string or an SDDL alias ("LA", "BA", ...)
      def normalize_sid(text)
        psid = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
        raise Unavailable, "ConvertStringSidToSidW failed (#{last_error})" if fn('advapi32.dll', 'ConvertStringSidToSidW', [PTR, PTR], INT).call(wide(text), psid).zero?

        sid = psid[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')
        str = 0
        begin
          out = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
          raise Unavailable, "ConvertSidToStringSidW failed (#{last_error})" if fn('advapi32.dll', 'ConvertSidToStringSidW', [PTR, PTR], INT).call(sid, out).zero?

          str = out[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')
          read_wide(Fiddle::Pointer.new(str))
        ensure
          free_sd(str) unless str.zero? # the string the conversion allocated
          free_sd(sid)                  # and the SID the first one allocated, also when the second conversion failed
        end
      end

      # the DACL of a path as an SDDL string
      def dacl_sddl(path)
        psd = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
        rc = fn('advapi32.dll', 'GetNamedSecurityInfoW', [PTR, INT, INT, PTR, PTR, PTR, PTR, PTR], INT).call(wide(path), 1, 4, nil, nil, nil, nil, psd)
        raise Unavailable, "GetNamedSecurityInfoW failed (#{rc})" unless rc.zero?

        sd = psd[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')
        out = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
        raise Unavailable, "ConvertSecurityDescriptorToStringSecurityDescriptorW failed (#{last_error})" if
          fn('advapi32.dll', 'ConvertSecurityDescriptorToStringSecurityDescriptorW', [PTR, INT, INT, PTR, PTR], INT).call(sd, 1, 4, out, nil).zero?

        s = read_wide(Fiddle::Pointer.new(out[0, Fiddle::SIZEOF_VOIDP].unpack1(Fiddle::SIZEOF_VOIDP == 8 ? 'Q' : 'L')))
        free_sd(sd)
        s
      end
    end
    end
  end
end
