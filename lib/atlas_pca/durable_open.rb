# frozen_string_literal: true

# Openers of the durable stores over an atomic key/value store: the operation-record store over any kv with #update (the reference's
# durableOperationStore) and the budget ledger over a durable-state directory (openDurableBudgetLedger).
module AtlasPca
  module_function

  # An OperationStore over any atomic kv (#get, #update; e.g. open_durable_state(dir: ...): crash-safe and multi-process-safe on one
  # host). `prefix` namespaces the keys; `scope` is 'shared' (default) or 'process'. It has no list_open: recover a known id with
  # recover_operation.
  def durable_operation_store(kv, prefix: 'pca-op:', scope: 'shared') = KvOperationStore.new(kv, prefix: prefix, scope: scope)

  # The reference budget ledger over durable-state files in `dir`: crash-safe, hash-chained, multi-process safe on one host.
  def open_durable_budget_ledger(dir:, lock_timeout_ms: nil)
    opts = { dir: dir }
    opts[:lock_timeout_ms] = lock_timeout_ms unless lock_timeout_ms.nil?
    KvBudgetLedger.new(open_durable_state(**opts), true)
  end
end
