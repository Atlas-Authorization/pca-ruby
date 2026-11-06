# frozen_string_literal: true
# Consistency-proof nodes are SHA-256 outputs (TS 80dfe7a25): with old size 1 the old root is the starting hash, so a 31- or
# 33-byte old root (or path element) plus a crafted new root verified as consistent before the length check (fail-open).
module MutationKill
  module ConsistencyLen
    module_function

    def h(x) = Digest::SHA256.digest(x)
    # [old_root, path, new_root] for {oldSize: 1, newSize: 2}: root1 = a, root2 = H(0x01 || a || c)
    def case_for(a, c) = [AtlasPca.b64e(a), [AtlasPca.b64e(c)], AtlasPca.b64e(h("\x01".b + a + c))]
    def ledger?(o, p, n) = AtlasPca.verify_ledger_consistency(o, n, { 'oldSize' => 1, 'newSize' => 2, 'path' => p })
    def mesh?(o, p, n) = AtlasPca.mesh_consistency?(o, n, { 'oldSize' => 1, 'newSize' => 2, 'path' => p })
  end

  t('ledger + mesh consistency: a 31/33-byte old root or path node is refused, the 32-byte control verifies') do
    c = ConsistencyLen
    good = ("\x07".b * 32)
    ok = [c.case_for(good, "\x09".b * 32)].all? { |x| c.ledger?(*x) == true && c.mesh?(*x) == true }
    bad = [31, 33].flat_map { |n| [c.case_for("\x07".b * n, good), c.case_for(good, "\x09".b * n)] }
    ok && bad.all? { |x| c.ledger?(*x) == false && c.mesh?(*x) == false }
  end
end
