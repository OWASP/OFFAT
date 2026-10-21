# Intentionally vulnerable Ruby fixture (Rails-style params).
class UsersController
  def search
    q = params[:q]
    User.where("name = '" + q + "'")       # VULN sqli
  end

  def run
    host = params[:host]
    system("ping -c 1 " + host)            # VULN command_injection
  end
end
