class BubblesController < ApplicationController
  include BucketScoped

  before_action :set_bubble, only: %i[ show edit update ]

  def index
    @bubbles = @bucket.bubbles
    @bubbles = params.include?(:popped) ? @bubbles.popped : @bubbles.not_popped

    if params[:term].present?
      @bubbles = @bubbles.mentioning(params[:term])
    end

    if params[:tag_id]
      @tag = Current.account.tags.find(params[:tag_id])
      @bubbles = @bubbles.tagged_with(@tag)
    end

    if params[:assignee_id]
      @assignee = @bucket.users.find(params[:assignee_id])
      @bubbles = @bubbles.assigned_to(@assignee)
    end
  end

  def new
    @bubble = @bucket.bubbles.build
  end

  def create
    @bubble = @bucket.bubbles.create!
    redirect_to bucket_bubble_url(@bucket, @bubble)
  end

  def show
  end

  def edit
  end

  def update
    @bubble.update!(bubble_params)
    redirect_to bucket_bubble_url(@bucket, @bubble)
  end

  private
    def set_bubble
      @bubble = @bucket.bubbles.find(params[:id])
    end

    def bubble_params
      params.require(:bubble).permit(:title, :color, :due_on, :image, tag_ids: [])
    end
end
