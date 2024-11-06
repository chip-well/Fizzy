require "test_helper"

class BucketsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as :kevin
  end

  test "index" do
    get buckets_url
    assert_response :success
  end

  test "new" do
    get new_bucket_url
    assert_response :success
  end

  test "create" do
    assert_difference -> { Bucket.count }, +1 do
      post buckets_url, params: { bucket: { name: "Remodel Punch List" } }
    end

    bucket = Bucket.last
    assert_redirected_to bubbles_path(bucket_ids: [ bucket ])
    assert_includes bucket.users, users(:kevin)
    assert_equal "Remodel Punch List", bucket.name
  end

  test "edit" do
    get edit_bucket_url(buckets(:writebook))
    assert_response :success
  end

  test "update" do
    patch bucket_url(buckets(:writebook)), params: { bucket: { name: "Writebook bugs" }, user_ids: users(:david, :jz).pluck(:id) }

    assert_redirected_to bubbles_path(bucket_ids: [ buckets(:writebook) ])
    assert_equal "Writebook bugs", buckets(:writebook).reload.name
    assert_equal users(:david, :jz), buckets(:writebook).users
  end

  test "destroy" do
    assert_difference -> { Bucket.count }, -1 do
      delete bucket_url(buckets(:writebook))
      assert_redirected_to buckets_url
    end
  end
end
