class AuthClient

    def initialize
        @region = ENV["AWS_REGION"]
        @pool_id = ENV["AWS_COGNITO_POOL_ID"]
        @client_id = ENV["AWS_COGNITO_CLIENT_ID"]
        @base_idp_uri = "https://cognito-idp.%s.amazonaws.com" % [ @region ]
    end

    def verification_token(request)
      # "Bearer ~"
      return nil_auth unless request.headers.key?("Authorization")
    
      # Bearer ～ を削除した状態
      token = request.headers["Authorization"]&.split&.last
    
      return :nil_token if token.blank?

      # 公開鍵のセットを取得
      jwk_uri = URI.join(@base_idp_uri, "/#{@pool_id}/.well-known/jwks.json").to_s
      jwks_json = JSON.parse(URI.open(jwk_uri).read)
      jwks = JSON::JWK::Set.new(jwks_json)
    
      # 公開鍵の検証
      begin
        verified_token = JSON::JWT.decode(token, jwks)
      rescue
        return :invalid_token_error
      end
    
      # claim 検証
      # 発行者の確認
      iss = URI.join(@base_idp_uri, "/#{@pool_id}").to_s
      return :iss_error unless verified_token[:iss] == iss
      # id_token のみを許可
      return :token_use_error unless verified_token[:token_use] == "id"
      return :client_id_error unless verified_token[:aud] == @client_id
      # subject(unique)
      return :no_present_sub_error unless verified_token[:sub].present?
      # 有効期限の確認
      return :expired_error unless Time.at(verified_token[:iat]) <= Time.now() &&
                                   Time.at(verified_token[:exp]) > Time.now()

      return :verify
    end
end
