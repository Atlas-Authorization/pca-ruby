# frozen_string_literal: true

require 'json'
require_relative 'refund_app'

grants = JSON.parse(File.read(ENV.fetch('PCA_GRANTS', File.join(__dir__, 'grants.json'))))
app, = RefundApp.build(grants: grants, audience: ENV.fetch('PCA_AUDIENCE', 'payments-rs'))
run app
