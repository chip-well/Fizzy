class Accounts::SettingsController < ApplicationController
  def show
    @account = Account.sole
  end
end
