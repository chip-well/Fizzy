class Reaction < ApplicationRecord
  belongs_to :comment, touch: true
  belongs_to :reacter, class_name: "User", default: -> { Current.user }

  scope :ordered, -> { order(:created_at) }

  validates_presence_of :content

  def all_emoji?
    content.match? /\A(\p{Emoji_Presentation}|\p{Extended_Pictographic}|\uFE0F)+\z/u
  end
end
