module Filter::Params
  extend ActiveSupport::Concern

  PERMITTED_PARAMS = [ :assignment_status, :indexed_by, assignee_ids: [], assigner_ids: [], bucket_ids: [], tag_ids: [], terms: [] ]

  class_methods do
    def find_by_params(params)
      find_by params_digest: digest_params(params)
    end

    def digest_params(params)
      Digest::MD5.hexdigest normalize_params(params).to_json
    end

    def normalize_params(params)
      params.to_h.compact_blank.reject(&method(:default_value?)).sort
    end
  end

  included do
    before_save { self.params_digest = self.class.digest_params(as_params) }
  end

  # +as_params+ uses `resource#ids` instead of `#resource_ids`
  # because the latter won't work on unpersisted filters.
  def as_params
    {}.tap do |params|
      params[:indexed_by]        = indexed_by
      params[:assignment_status] = assignment_status
      params[:terms]             = terms
      params[:tag_ids]           = tags.ids
      params[:bucket_ids]        = buckets.ids
      params[:assignee_ids]      = assignees.ids
      params[:assigner_ids]      = assigners.ids
    end.compact_blank.reject(&method(:default_value?))
  end

  def as_params_without(key, value)
    as_params.tap do |params|
      params[key].delete(value.to_i) if params[key].is_a?(Array)
      params.delete(key) if params[key] == value.to_s
    end
  end
end
