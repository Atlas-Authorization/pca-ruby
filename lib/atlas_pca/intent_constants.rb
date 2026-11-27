# frozen_string_literal: true

module AtlasPca
  # Every exported constant of the five intent modules the reference's `intent-misc2` corpus covers (intent-artifacts, intent-required,
  # intent-classifier, intent-acc, intent-history), with the source text of the patterns, as one view.
  module IntentConstants
    ACC_ID_RE_SOURCE = '^[A-Za-z0-9_]{1,64}$'
    KID_RE_SOURCE = '^[A-Za-z0-9_.:-]{1,64}$'

    module_function

    def view
      v2 = IntentV2
      ia = IntentArtifacts
      ir = IntentRequired
      {
        'DATA_CLASS_RE' => { '$regex' => ia::DATA_CLASS_RE_SOURCE }, 'INTENT_NAME_RE' => { '$regex' => ia::INTENT_NAME_RE_SOURCE },
        'PARAM_SEGMENT_RE' => { '$regex' => ia::PARAM_SEGMENT_RE_SOURCE }, 'SUITE_MEMBERS' => ia::SUITE_MEMBERS,
        'FRICTIONS' => AtlasPca::FRICTIONS, 'INTENT_ACTION_DOMAIN' => IntentJit::INTENT_ACTION_DOMAIN, 'INTENT_PROBLEM_KINDS' => ir::INTENT_PROBLEM_KINDS,
        'INTENT_REQUIRED_DOMAIN' => AtlasPca::INTENT_REQUIRED_DOMAIN, 'PROBLEM_BASE' => ir::PROBLEM_BASE,
        'INTENT_CLASSIFIER_DOMAIN' => AtlasPca::INTENT_CLASSIFIER_DOMAIN, 'INTENT_CLASSIFIER_REF_DOMAIN' => AtlasPca::INTENT_CLASSIFIER_REF_DOMAIN,
        'MAX_CLASSIFIER_LABELS' => AtlasPca::MAX_CLASSIFIER_LABELS, 'MAX_COMMITTED_CLASSES' => AtlasPca::MAX_COMMITTED_CLASSES,
        'ACC_AGGS' => v2::ACC_AGGS, 'ACC_ID_RE' => { '$regex' => ACC_ID_RE_SOURCE }, 'ACC_RECEIPT_CORE_DOMAIN' => AtlasPca::ACC_RECEIPT_CORE_DOMAIN,
        'ACC_RECEIPT_DOMAIN' => v2::ACC_RECEIPT_DOMAIN, 'ACC_RECEIPT_REF_DOMAIN' => v2::ACC_RECEIPT_REF_DOMAIN, 'ACC_RESERVE_DOMAIN' => v2::ACC_RESERVE_DOMAIN,
        'ACC_SCOPES' => AtlasPca::ACC_SCOPES, 'DEFAULT_MAX_KEYSET_AGE_MS' => v2::DEFAULT_MAX_KEYSET_AGE_MS,
        'DEFAULT_MAX_RECEIPT_AGE_MS' => v2::DEFAULT_MAX_RECEIPT_AGE_MS, 'KID_RE' => { '$regex' => KID_RE_SOURCE },
        'MAX_MONITOR_WITHIN' => v2::MAX_MONITOR_WITHIN, 'MAX_RECEIPT_LIFETIME_MS' => v2::MAX_RECEIPT_LIFETIME_MS,
        'MAX_SESSION_ACCUMULATORS' => v2::MAX_SESSION_ACCUMULATORS, 'MAX_SESSION_MONITORS' => v2::MAX_SESSION_MONITORS, 'MONITOR_KINDS' => v2::MONITOR_KINDS,
        'RECEIPT_SKEW_MS' => v2::RECEIPT_SKEW_MS, 'SEQUENCER_KEYS_DOMAIN' => v2::SEQUENCER_KEYS_DOMAIN, 'SEQUENCER_KEYS_REF_DOMAIN' => v2::SEQUENCER_KEYS_REF_DOMAIN,
        'COUNTED_STATUSES' => AtlasPca::COUNTED_STATUSES, 'EVENT_STATUSES' => AtlasPca::EVENT_STATUSES
      }
    end
  end
end
