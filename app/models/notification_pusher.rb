class NotificationPusher
  include Rails.application.routes.url_helpers

  attr_reader :notification

  def initialize(notification)
    @notification = notification
  end

  def push
    return unless should_push?

    build_payload.tap do |payload|
      push_to_user(payload)
    end
  end

  private
    def should_push?
      notification.user.push_subscriptions.any? &&
        !notification.creator.system? &&
        notification.user.active?
    end

    def build_payload
      case notification.source_type
      when "Event"
        build_event_payload
      when "Mention"
        build_mention_payload
      else
        build_default_payload
      end
    end

    def build_event_payload
      event = notification.source
      card = event.card

      case event.action
      when "comment_created"
        {
          title: "RE: #{card_notification_title(card)}",
          body: comment_notification_body(event),
          path: collection_card_path(card.collection, card)
        }
      when "card_assigned"
        {
          title: card_notification_title(card),
          body: "Assigned to you by #{event.creator.name}",
          path: collection_card_path(card.collection, card)
        }
      when "card_published"
        {
          title: card_notification_title(card),
          body: "Added by #{event.creator.name}",
          path: collection_card_path(card.collection, card)
        }
      when "card_closed"
        {
          title: card_notification_title(card),
          body: card.closure ? "Closed as \"#{card.closure.reason}\" by #{event.creator.name}" : "Closed by #{event.creator.name}",
          path: collection_card_path(card.collection, card)
        }
      when "card_reopened"
        {
          title: card_notification_title(card),
          body: "Reopened by #{event.creator.name}",
          path: collection_card_path(card.collection, card)
        }
      else
        {
          title: card_notification_title(card),
          body: event.creator.name,
          path: collection_card_path(card.collection, card)
        }
      end
    end

    def build_mention_payload
      mention = notification.source
      card = mention.card

      {
        title: "#{mention.mentioner.first_name} mentioned you",
        body: mention.source.mentionable_content.truncate(200),
        path: collection_card_path(card.collection, card)
      }
    end

    def build_default_payload
      {
        title: "New notification",
        body: "You have a new notification",
        path: notifications_path
      }
    end

    def push_to_user(payload)
      subscriptions = notification.user.push_subscriptions
      enqueue_payload_for_delivery(payload, subscriptions)
    end

    def enqueue_payload_for_delivery(payload, subscriptions)
      Rails.configuration.x.web_push_pool.queue(payload, subscriptions)
    end

    def card_notification_title(card)
      card.title.presence || "Card #{card.id}"
    end

    def comment_notification_body(event)
      comment = event.eventable
      strip_tags(comment.body.to_s).truncate(200)
    end

    def strip_tags(text)
      ActionView::Base.full_sanitizer.sanitize(text)
    end
end
