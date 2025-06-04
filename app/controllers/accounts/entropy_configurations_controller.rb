class Accounts::EntropyConfigurationsController < ApplicationController
  def update
    Account.sole.default_entropy_configuration.update!(entropy_configuration_params)

    redirect_to account_settings_path, notice: "Account updated"
  end

  private
    def entropy_configuration_params
      params.expect(entropy_configuration: [ :auto_close_period, :auto_reconsider_period ])
    end
end
