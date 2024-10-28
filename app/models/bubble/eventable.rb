module Bubble::Eventable
  extend ActiveSupport::Concern

  included do
    after_create -> { track_event :created }
  end

  private
    def track_event(action, creator: Current.user, **particulars)
      find_or_capture_event_summary.events.create! action: action, creator: creator, particulars: particulars
    end

    def find_or_capture_event_summary
      transaction do
        messages.last&.event_summary || capture(EventSummary.new).event_summary
      end
    end
end
