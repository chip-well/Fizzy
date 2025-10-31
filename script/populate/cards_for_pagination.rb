require_relative "../../config/environment"

CARDS_COUNT = 10_000

ApplicationRecord.current_tenant = "897362094"
account = Account.sole
user = User.first
user.sessions.create!
Current.session = user.sessions.last
collection = Collection.first

CARDS_COUNT.times do |index|
  card = collection.cards.create!(title: "Doing card #{index}", creator: user, status: :published)
  puts "."
end
