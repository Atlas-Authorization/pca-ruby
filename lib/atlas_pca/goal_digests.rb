# frozen_string_literal: true

require_relative 'goal_js'

module AtlasPca
  # Content digests of the goal-to-decision flow (the TypeScript reference is @atlasauth/pca-goal `digests`): strict canonical
  # JSON, safe integers only (a float, nil key or cycle raises).
  module GoalDigests
    module_function

    # Digest of the whole signed Goal.
    def goal_digest(goal) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-ir/v1', 'goal' => goal })

    # Digest of the instruction text a goal was interpreted from (what `Goal.nlDigest` must equal).
    def nl_digest(instruction) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-nl/v1', 'text' => instruction })

    # Digest of the model set that produced a goal: sorted (UTF-16 order), de-duplicated ids.
    def model_set_digest(models)
      ids = GoalJs.req_list(models).uniq.sort_by { |m| GoalJs.u16key(m) }
      AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-model-set/v1', 'models' => ids })
    end

    # Digest of an approval's covered fields: any changed member changes it.
    def approval_digest(body) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/goal-approval-body/v1', 'body' => body })
  end
end
