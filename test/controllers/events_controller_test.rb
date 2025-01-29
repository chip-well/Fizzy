require "test_helper"

class EventsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as :kevin

    events(:layout_assignment_jz).update!(created_at: Time.current.beginning_of_day + 8.hours)
  end

  test "index" do
    get events_url

    assert_select "div.event__wrapper[style='grid-area: 17/1']" do
      assert_select "strong", text: "Layout is broken"
    end
  end

  test "index with a specific timezone" do
    cookies[:timezone] = "America/New_York"

    get events_url

    assert_select "div.event__wrapper[style='grid-area: 22/1']" do
      assert_select "strong", text: "Layout is broken"
    end
  end
end
