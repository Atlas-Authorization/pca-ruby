# frozen_string_literal: true

# Rails integration: a controller concern that gates actions on a valid PCActn by driving RackMiddleware (default-deny, the full
# authorize pipeline unless signature_only). Rails is a soft dependency: this file never requires it, the host app includes the
# concern and Rails supplies before_action / render.
#
#   class RefundsController < ApplicationController
#     include AtlasPca::Rails::Controller
#     pca_protect audience: 'rs-billing', resolve_grant: ->(ref) { GRANTS[ref] }, only: :create,
#                 operation: ->(env) { { verb: 'payments.send', resource: 'payments/1', params: {} } }
#     def create = render(json: { ok: true, verb: pca_context['operation']&.verb })
#   end
require 'stringio'
require_relative 'rack_middleware'

module AtlasPca
  module Rails
    module Controller
      def self.included(base)
        base.extend(ClassMethods)
      end

      module ClassMethods
        # Options are RackMiddleware's (audience:, resolve_grant:, authorize:, signature_only:, ...) plus operation:, a callable
        # env -> operation (from your routing, never from the PCActn) that turns the authorize path on; before_action filters
        # (only:, except:, if:, unless:) pass through. Without operation: or authorize: or signature_only: it raises.
        def pca_protect(operation: nil, **options)
          filters = options.slice(:only, :except, :if, :unless)
          options = options.except(:only, :except, :if, :unless)
          if operation.nil? && options[:authorize].nil? && options[:signature_only] != true
            raise ArgumentError, 'pca_protect: operation: (the operation each request executes) or authorize: is required; ' \
                                 'signature_only: true is the explicit unbound opt-in'
          end
          options[:authorize] = (options[:authorize] || {}).merge(operation: operation) unless operation.nil?
          captured = nil
          mw = RackMiddleware.new(->(env) { captured = env['pca']; [200, {}, []] }, **options)
          before_action(**filters) do
            captured = nil
            status, headers, body = mw.call(request.env)
            if captured
              @pca_context = captured
            else
              headers.each { |k, v| response.set_header(k, v) }
              render(plain: body.each.to_a.join, status: status, content_type: 'application/json')
            end
          end
        end
      end

      # The verdict, PCActn and (authorize path) bound operation of the verified request.
      def pca_context = @pca_context
    end
  end
end
