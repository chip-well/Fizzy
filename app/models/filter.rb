class Filter < ApplicationRecord
  include Summarized

  KNOWN_PARAMS = [ :indexed_by, :assignments, bucket_ids: [], assignee_ids: [], tag_ids: [] ]
  INDEXES = %w[ most_active most_discussed most_boosted newest oldest popped ]

  belongs_to :creator, class_name: "User", default: -> { Current.user }

  has_one :account, through: :creator

  has_and_belongs_to_many :tags
  has_and_belongs_to_many :buckets
  has_and_belongs_to_many :assignees, class_name: "User", join_table: "assignees_filters", association_foreign_key: "assignee_id"

  before_validation :denormalize_resource_ids
  before_validation :remove_default_params

  store_accessor :params, :indexed_by
  store_accessor :params, :assignments

  class << self
    def default_params
      { "indexed_by" => "most_active" }
    end

    def create_or_find_by_params!(params)
      filter = new params
      filter.save!
      filter
    rescue ActiveRecord::RecordNotUnique
      find_by! params: filter.params
    end
  end

  def bubbles
    @bubbles ||= begin
      result = creator.accessible_bubbles.indexed_by(indexed_by)
      result = result.active unless indexed_by.popped?
      result = result.unassigned if assignments.unassigned?
      result = result.in_bucket(buckets.ids) if buckets.present?
      result = result.tagged_with(tags.ids) if tags.present?
      result = result.assigned_to(assignees.ids) if assignees.present?
      result
    end
  end

  def to_params
    params.merge(tag_ids: tags.ids, assignee_ids: assignees.ids, bucket_ids: buckets.ids).then do |params|
      ActionController::Parameters.new(params).permit(*KNOWN_PARAMS).tap do |params|
        params[:filter_id] = id if persisted?
      end
    end
  end

  def indexed_by
    (params["indexed_by"] || self.class.default_params["indexed_by"]).inquiry
  end

  def assignments
    params["assignments"].to_s.inquiry
  end

  def savable?
    !bucket_default?
  end

  def cacheable?
    buckets.exists?
  end

  def cache_key
    ActiveSupport::Cache.expand_cache_key buckets.cache_key_with_version, super
  end

  def resource_removed(kind:, id:)
    params["#{kind}_ids"] = Array(params["#{kind}_ids"]).without(id).presence
    non_default_params.blank? ? destroy : touch
  end

  private
    def remove_default_params
      self[:params] = non_default_params.compact_blank
    end

    def non_default_params
      params.reject { |k, v| self.class.default_params[k] == v }
    end

    # `denormalize_resource_ids` stores ids in the params column to enforce uniqueness
    def denormalize_resource_ids
      params[:bucket_ids] = buckets.ids.presence
      params[:tag_ids] = tags.ids.presence
      params[:assignee_ids] = assignees.ids.presence
    end

    def bucket_default?
      non_default_params.keys == %w[ bucket_ids ] && buckets.one?
    end
end
