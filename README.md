Flutter Application のバックエンドとして、Rails で REST API を開発しています。
認証・認可の役割そのものを API サーバー自体に持たせたくなかったため、Flutter 側で、Cognito から直接認証情報を取得しています。
特定のユーザーのみに実行を許可する API を構築するために、Flutter 側からのリクエストに付与されている Authorization token(JWT) を検証する仕組みをAPI サーバー側に用意することにしました。

JWT の検証には、json-jwt を使用しています。
https://github.com/nov/json-jwt

# 検証ステップ
AWS が検証のステップを公開していたので、こちらを参考に構築していきます。
    https://docs.aws.amazon.com/ja_jp/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html

## JWT トークンの署名を検証
0. クライアントからリクエストを受け取る
    リクエストには、Authorization ヘッダーに Bearer トークンとして id token を含めることにします。

    ```
        Authorization: Bearer id-token
    ```
    
    **ID token の例.(実際はもっと長いです)**
    ```
     eyJhbGsInR5cCI6IkpXVCJ9.eyJIwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2
    ```
2. ID トークンを復号化する
   受け取った ID トークンを復号化します。
   ID トークンは、header, payload, signature の3つの JSON から構成されています。
   これらの JSON は `.` 区切りで URL safe な形式で表現される JWT と呼ばれます。
   なお、header, payload は base64 encode されており、利用の際は decode が必要です。

   **header**
   ```json
   {
      "kid": "xxxxxxxxxxxxxxxxxxxxxxxxx",
      "alg": "RS256"
    }
   ```

   **payload**

   ```json
   {
      "sub": "xxxxxx-xxxxxx-xxxxxx",
      "email_verified": true,
      "iss": "https://cognito-idp.{region}.amazonaws.com/{pool_id}",
      "cognito:username": "xxxx-xxxx-xxxxx",
      "origin_jti": "yyyy-yyyyyy-yyyyy",
      "aud": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "event_id": "xxxxxxxx-xxxxxxxxxxx-xxxxxxxxxxxxxx",
      "token_use": "id",
      "auth_time": {unix_time},
      "exp": {unix_time},
      "iat": {unix_time},
      "jti": "xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxxx",
      "email": "example@example.com"
   }
   ```
   
4. 公開鍵(JWK) の Key ID と、ID トークン側の Key ID を比較する
5. 署名を比較する     
    ID トークンの header には、検証に必要な情報が含まれており、header の kid は公開鍵(JWK) の kid の比較ができ、また、alg に格納されている鍵生成アルゴリズムから、JWT の署名検証が可能になります。

    各属性については、こちらの記事がわかりやすかったです。

    https://meetup-jp.toast.com/3511
    https://zenn.dev/mikakane/articles/tutorial_for_jwt

## クレームの検証
payload を検証していきます。
1. 有効期限が切れていないことを確認する
    - exp に unixtime として格納されている
2. aud クレームと Cognito ユーザープールで作成されたアプリクライアント ID が一致することを確認する
   - aud
3. 発行者(iss) クレームと Cognito ユーザープール ID が一致することを確認する
   - iss
4. token_use クレームを確認する
   - token_use
       - id トークンのみを使用するなら token_use == id を検証する

# Ruby で検証ステップをこなしていく

## JWT トークンの署名を検証
先述したステップに合わせていきます。

0. クライアントからリクエストを受け取る
    Bearer がついているので、id-token のみを抽出しておきます。

    ```ruby
        raw_id_token = request.headers["Authorization"]&.split&.last
    ```
    
1. ID トークンを復号化する
2. 公開鍵(JWK) の Key ID と、ID トークン側の Key ID を比較する
3. 署名を比較する
   json-jwt のデコードは公開鍵のリストとトークンを渡すだけで署名を検証してくれます。
   Cognito の場合、公開鍵は複数あり、なおかつ変更する可能性があるそうです。
   本番環境で使用するなら、キャッシュ戦略が必要になりそうです。

   ```ruby
        # 公開鍵を取得
        uri = URI.join(@base_idp_uri, "/#{@pool_id}/.well-known/jwks.json").to_s
        jwks_json = JSON.parse(URI.open(uri).read)
        jwks = JSON::JWK::Set.new(jwks_json)
        # 公開鍵の検証
        verified_token = JSON::JWT.decode(token, jwks)
        # => payload が返ってくる
   ```

## クレームの検証
payload の検証は一気に書きます。

1. 有効期限が切れていないことを確認する(現在時刻が iat 以降、exp 未満)
2. aud クレームと Cognito ユーザープールで作成されたアプリクライアント ID が一致することを確認する
3. 発行者(iss) クレームと Cognito ユーザープール ID が一致することを確認する
4. token_use クレームを確認する

```ruby
    # claim 検証
    # 有効期限の確認
    return :expired_error unless Time.at(verified_token[:iat]) <= Time.now() &&
                                 Time.at(verified_token[:exp]) > Time.now()
    # id_token のみを許可
    return :token_use_error unless verified_token[:token_use] == "id"
    return :client_id_error unless verified_token[:aud] == @client_id
    # 発行者の確認
    return :iss_error unless verified_token[:iss] == get_iss()
    # subject(unique)
    return :no_present_sub_error unless verified_token[:sub].present?
```

# コード全文
AuthClient というクラスのインスタンスメソッドとして実装しています。
```ruby
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
```

# 使い方
先ほどの `verification_token` を、controller の before_action に指定しています。

**app/controllers/api/v1/base_controller.rb**
```ruby
require "./lib/auth/cognito/cognito_client"

class Api::V1::BaseController < ApplicationController

  def verification_user
    client = AuthClient.new()
    auth = client.verification_token(request)
    if auth != :verify
      render json: {
        error: "Invalid token #{auth}",
        status: :unauthorized
      }
      return
    end
  end
end
```

**app/controllers/api/v1/soregashi_controller.rb**
```ruby
class Api::V1::SoregashiController < Api::V1::BaseController
  before_action :verification_user

  def index
    render json: {message: "Soregashi"}, status: :ok
  end
end
```

# 参考

https://github.com/nov/json-jwt/wiki
https://qiita.com/TakahikoKawasaki/items/498ca08bbfcc341691fe
https://qiita.com/TakahikoKawasaki/items/e37caf50776e00e733be
https://qiita.com/ya-mada/items/154ea6e10f9f788bfdd5
https://qiita.com/tmak_tsukamoto/items/109ed73546e6522f4424
https://zenn.dev/mikakane/articles/tutorial_for_jwt
https://meetup-jp.toast.com/3511
https://ritou.hatenablog.com/entry/2020/03/31/142550
https://github.com/mheffner/rails-cognito-example/tree/master
