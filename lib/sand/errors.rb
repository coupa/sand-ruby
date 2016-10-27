module Sand
  class TokenIsEmptyError < StandardError
  end

  class TokenNotAuthorizedError < StandardError
  end

  class UnsupportedResponseError < StandardError
  end
end
