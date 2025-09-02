class PeriodHighlights < ApplicationRecord
  class << self
    def create_or_find_for(collections, starts_at:, duration: 1.week)
      self.for(collections, starts_at:, duration:) || create_for(collections, starts_at:, duration:)
    end

    def for(collections, starts_at:, duration: 1.week)
      period = Period.new(collections, starts_at:, duration:)
      find_by(**period.as_params) if period.has_activity?
    end

    private
      def create_for(collections, starts_at:, duration: 1.week)
        period = Period.new(collections, starts_at:, duration:)

        if period.has_activity?
          summarizer = Event::Summarizer.new(period.events)
          summarized_content = summarizer.summarized_content # outside of transaction as this can be slow

          create_or_find_by!(**period.as_params) do |record|
            record.content = summarized_content
            record.cost_in_microcents = summarizer.cost.in_microcents
          end
        end
      end
  end

  def ends_at
    starts_at + duration
  end

  def to_html
    renderer = Redcarpet::Render::HTML.new
    markdowner = Redcarpet::Markdown.new(renderer, autolink: true, tables: true, fenced_code_blocks: true, strikethrough: true, superscript: true,)
    markdowner.render(content).html_safe
  end
end
