require_relative "production"

Rails.application.configure do
  config.action_mailer.smtp_settings[:domain] = "fizzy.37signals-staging.com"
  config.action_mailer.smtp_settings[:address] = "smtp-outbound-staging"
  config.action_mailer.default_url_options     = { host: "fizzy.37signals-staging.com", protocol: "https" }
  config.action_controller.default_url_options = { host: "fizzy.37signals-staging.com", protocol: "https" }
end
