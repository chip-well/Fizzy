Rails.application.configure do
  config.active_storage.service = :purestorage
  config.structured_logging.logger = ActiveSupport::Logger.new(STDOUT)

  config.action_controller.default_url_options = { host: "app.fizzy.do", protocol: "https" }
  config.action_mailer.default_url_options     = { host: "app.fizzy.do", protocol: "https" }
  config.action_mailer.smtp_settings = { domain: "app.fizzy.do", address: "smtp-outbound", port: 25, enable_starttls_auto: false }
end
