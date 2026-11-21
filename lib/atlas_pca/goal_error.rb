# frozen_string_literal: true

module AtlasPca
  module Goal
    # A goal, ontology, action or history that does not fit the IR (the reference's IrError).
    class IrError < StandardError
      def initialize(msg = nil) = super("pca-goal: #{msg}")
    end
  end
end
