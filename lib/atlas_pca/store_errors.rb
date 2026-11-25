# frozen_string_literal: true

module AtlasPca
  # Typed failures shared by the durable stores (the reference's RangeError and the coded LedgerStoreError, BondStoreError and
  # BudgetLedgerError). `code` is stable; the message is "<code>: <text>" for the coded errors. An argument error is Ruby's own RangeError.
  class StoreCodedError < StandardError
    attr_reader :code

    def initialize(code, message)
      super("#{code}: #{message}")
      @code = code
    end
  end

  # The typed failure of every store-backed ledger operation.
  class LedgerStoreError < StoreCodedError; end

  # The typed failure of every store-backed bond operation.
  class BondStoreError < StoreCodedError; end

  # The typed failure of the aggregate budget ledger.
  class BudgetLedgerError < StoreCodedError; end

  # The stable code of an error: its `code` for a coded error, 'RangeError' for an argument error, else 'Error'.
  def self.store_error_code(e)
    return e.code if e.is_a?(StoreCodedError)

    e.is_a?(::RangeError) ? 'RangeError' : 'Error'
  end
end
