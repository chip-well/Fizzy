Rails.application.configure do
  if Rails.root.join("tmp/structured-logging.txt").exist?
    config.structured_logging.logger = ActiveSupport::Logger.new("log/structured-development.log")
  end
end
