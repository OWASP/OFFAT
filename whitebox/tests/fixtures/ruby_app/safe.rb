class SafeController
  def count
    n = params[:n].to_i                    # SAFE: to_i coercion
    User.where("id = " + n.to_s)
  end
end
