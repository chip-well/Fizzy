require "test_helper"

class Bubbles::WatchesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as :kevin
  end

  test "create" do
    bubbles(:logo).set_watching(users(:kevin), false)

    assert_changes -> { bubbles(:logo).watched_by?(users(:kevin)) }, from: false, to: true do
      post bucket_bubble_watch_url(buckets(:writebook), bubbles(:logo))
    end

    assert_redirected_to bucket_bubble_watch_url(buckets(:writebook), bubbles(:logo))
  end

  test "destroy" do
    bubbles(:logo).set_watching(users(:kevin), true)

    assert_changes -> { bubbles(:logo).watched_by?(users(:kevin)) }, from: true, to: false do
      delete bucket_bubble_watch_url(buckets(:writebook), bubbles(:logo))
    end

    assert_redirected_to bucket_bubble_watch_url(buckets(:writebook), bubbles(:logo))
  end
end
