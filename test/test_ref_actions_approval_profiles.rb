# frozen_string_literal: true

# Replays the SPC expectation and CIBA approval details cases of the shared approval corpus (test-data/base-approval.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_approval_profiles'
require 'minitest/autorun'

class TestRefActionsApprovalProfiles < Minitest::Test
  P = AtlasPca::ActionsApprovalProfiles

  # same file format as the ref corpora, under its older name
  def self.load_corpus
    txt = Zlib::GzipReader.open(File.join(Ref::DATA, 'base-approval.json.gz'), &:read).force_encoding('UTF-8')
    d = AtlasPca::JsonParser.new(txt, true, true, json_text: true).parse_document
    Ref.unseed(d)['cases'].group_by { |c| c['fn'] }
  end

  BY_FN = load_corpus
  MAP = { 'spcExpectation' => P.method(:spc_expectation), 'cibaApprovalDetails' => P.method(:ciba_approval_details) }.freeze

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end
end
