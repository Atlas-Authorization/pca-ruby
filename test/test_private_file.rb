# frozen_string_literal: true

# Every private writer creates its file or directory owner-only: mode 0600 / 0700 on POSIX; on Windows a protected DACL with
# exactly one entry (full rights for the current user), read back from the file. Windows CI runs this file.
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/mpc_net/certs'
require 'minitest/autorun'
require 'tmpdir'
require 'json'

class TestPrivateFile < Minitest::Test
  PF = AtlasPca::PrivateFile

  def with_dir(&blk) = Dir.mktmpdir('pca-private') { |d| blk.call(d) }

  def assert_private(path, dir: false)
    assert PF.owner_only?(path, dir ? 0o700 : 0o600), "#{path} is not owner-only: #{PF.restriction(path).inspect}"
    r = PF.restriction(path)
    return if r.key?(:mode)

    assert_equal 1, r[:sddl].scan(/\(A;/).length, 'exactly one entry'
    assert r[:sddl].start_with?('D:P'), 'protected (no inherited entries)'
    assert_match(/\AD:P\(A;;FA;;;[^()]+\)\z/, r[:sddl]) # the trustee may be spelled as an alias ("LA"): owner_only? compares the SIDs
  end

  # the wide-string helper behind every Win32 path argument: NUL-terminated UTF-16LE bytes, non-ASCII included
  if PF.windows?
    def test_wide_is_nul_terminated_utf16le_binary
      w = PF::Win.wide("a\u00e9")
      assert_equal "a\x00\xE9\x00\x00\x00".b, w
      assert_equal Encoding::BINARY, w.encoding
    end
  end

  # a failed create reads the OS error right after the call: a missing directory is ENOENT and an existing file under CREATE_NEW is EEXIST
  def test_a_failed_create_reports_the_os_error
    with_dir do |d|
      assert_raises(Errno::ENOENT) { PF.open(File.join(d, 'no', 'such', 'f'), File::WRONLY | File::CREAT | File::EXCL) { nil } }
      f = File.join(d, 'x')
      PF.write(f, '1')
      assert_raises(Errno::EEXIST) { PF.open(f, File::WRONLY | File::CREAT | File::EXCL) { nil } }
    end
  end

  def test_open_creates_private_and_keeps_exclusive_create
    with_dir do |d|
      f = File.join(d, 'a')
      PF.open(f, File::WRONLY | File::CREAT | File::EXCL, binmode: true) { |io| io.write('x') }
      assert_private(f)
      assert_raises(Errno::EEXIST) { PF.open(f, File::WRONLY | File::CREAT | File::EXCL) { nil } }
      assert_equal 'x', File.binread(f)
    end
  end

  def test_write_append_and_truncate
    with_dir do |d|
      f = File.join(d, 'w')
      PF.write(f, 'one')
      PF.write(f, 'two')
      assert_equal 'two', File.binread(f)
      PF.open(f, File::WRONLY | File::APPEND | File::CREAT, binmode: true) { |io| io.write('+') }
      assert_equal 'two+', File.binread(f)
      assert_private(f)
    end
  end

  def test_mkdir_p_and_mktmpdir_are_private
    with_dir do |d|
      sub = File.join(d, 'x', 'state')
      PF.mkdir_p(sub)
      assert_private(sub, dir: true)
      PF.mkdir_p(sub) # idempotent
      t = PF.mktmpdir('pca-pf-')
      begin
        assert_private(t, dir: true)
      ensure
        FileUtils.remove_entry(t)
      end
      PF.mktmpdir('pca-pf-') { |b| assert_private(b, dir: true) }
    end
  end

  def test_durable_state_files_and_dir
    with_dir do |d|
      dir = File.join(d, 'ds')
      s = AtlasPca.open_durable_state(dir: dir)
      s.set('k', { 'n' => 1 })
      assert_private(dir, dir: true)
      Dir.children(dir).each { |n| assert_private(File.join(dir, n)) if File.file?(File.join(dir, n)) }
    end
  end

  def test_key_and_cert_writer
    with_dir do |d|
      id = AtlasPca::Mpc::Net::Certs.generate_identity(File.join(d, 'id'), 'n1')
      assert_private(File.join(d, 'id'), dir: true)
      assert_private(id.key_path)
    end
  end

  def test_revocation_and_witness_files
    with_dir do |d|
      f = File.join(d, 'witness.json')
      w = AtlasPca::FileMeshWitnessStore.new(f)
      w.save({})
      assert_private(f)
    end
  end

  def test_revocation_store_file
    with_dir do |d|
      f = File.join(d, 'rev.json')
      st = AtlasPca::Revoke::FileRevocationStore.new(f)
      st.add({ 'kind' => 'session', 'value' => 's1' })
      assert_private(f)
    end
  end

  def test_ciba_file_store_and_directory_kv
    with_dir do |d|
      f = File.join(d, 'approvals.json')
      assert AtlasPca::Ciba::FileApprovalStore.new(f).cas('k', 0, { 'a' => 1 })
      assert_private(f)
      dir = File.join(d, 'kv')
      kv = AtlasPca::Ciba.create_directory_kv(dir)
      assert kv.put_if_equals('k', nil, 'v')
      assert_private(dir, dir: true)
      files = Dir.children(dir).map { |n| File.join(dir, n) }.select { |n| File.file?(n) }
      refute_empty files
      files.each { |n| assert_private(n) }
    end
  end

  def test_scitt_log_file
    with_dir do |d|
      f = File.join(d, 'log.bin')
      s = AtlasPca::ScittLog::FileScittLogStore.open(f)
      s.close
      assert_private(f)
    end
  end

  def test_step_up_secret_file
    with_dir do |d|
      f = File.join(d, 'device.key')
      st = AtlasPca::StepUp::FileSecretStore.new(f)
      st.save(Random.bytes(32))
      assert_private(f)
      st.save(Random.bytes(32)) # an overwrite keeps it private
      assert_private(f)
    end
  end
end
