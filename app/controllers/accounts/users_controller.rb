class Accounts::UsersController < ApplicationController
  before_action :set_user, only: %i[ destroy ]
  before_action :ensure_permission_to_remove, only: :destroy

  def index
    @users = Current.account.users.active
  end

  def destroy
    @user.deactivate
    redirect_to users_path
  end

  private
    def set_user
      @user = Current.account.users.active.find(params[:id])
    end

    def ensure_permission_to_remove
      head :forbidden unless Current.user.can_remove?(@user)
    end
end
