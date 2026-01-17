# PyID - Enterprise-Grade OAuth2/OIDC SSO Identity Provider

Django製のエンタープライズグレード SSO IdP（Identity Provider）です。
複数のサービスで利用可能な、OAuth2 + OpenID Connect 対応の認証基盤です。

## 🎯 特徴

- **OAuth2 + OpenID Connect 完全対応**
  - Authorization Code Flow + PKCE
  - JWT ベースのトークン管理（RS256）
  - Refresh Token ローテーション

- **ユーザー管理**
  - UUID ベースのカスタム User モデル
  - Email ログイン対応
  - BAN / 強制ログアウト機能
  - 監査ログ記録

- **セキュリティ**
  - PKCE 強制
  - Token ブラックリスト（Redis）
  - force_logout_at による即座なログアウト
  - SameSite + Secure Cookie

- **スケーラビリティ**
  - PostgreSQL + Redis
  - Docker Compose で即起動
  - Gunicorn による本番対応

## 🚀 クイックスタート

### 前提条件
- Docker & Docker Compose
- Python 3.11+
- PostgreSQL 16
- Redis 7

### 起動

```bash
# リポジトリをクローン
git clone https://github.com/yunfie-twitter/PyID.git
cd PyID

# .env ファイルを作成
cp .env.example .env

# Docker Compose で起動
docker-compose up -d

# ログを確認
docker-compose logs -f django

# 管理画面にアクセス
# http://localhost:8000/admin/
# Email: admin@sso-idp.local
# Password: secure_admin_password（.env で変更可能）
```

## 📚 API ドキュメント

### OAuth2 / OIDC エンドポイント

#### Authorization Endpoint
```
GET /oauth/authorize
Parameters:
  - client_id: OAuth クライアント ID
  - redirect_uri: リダイレクト URI
  - response_type: "code"（固定）
  - scope: "openid profile email"
  - state: CSRF トークン
  - code_challenge: PKCE チャレンジ
  - code_challenge_method: "S256" または "plain"
  - nonce: optional（OIDC）
```

#### Token Endpoint
```
POST /oauth/token
Request Body:
  {
    "grant_type": "authorization_code",
    "client_id": "...",
    "client_secret": "...",
    "code": "...",
    "redirect_uri": "...",
    "code_verifier": "..."
  }

Response:
  {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "id_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }
```

#### UserInfo Endpoint（OIDC 準拠）
```
GET /api/userinfo
Headers:
  Authorization: Bearer <access_token>

Response:
  {
    "sub": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "email_verified": true,
    "username": "john_doe",
    "name": "John Doe",
    "picture": "https://example.com/avatar.jpg",
    "updated_at": "2026-01-17T12:00:00Z"
  }
```

#### OpenID Configuration
```
GET /.well-known/openid-configuration

自動で OIDC メタデータを返します
```

### 管理者 API

#### ユーザーをBAN
```
POST /api/admin/ban-user/{user_id}/
Headers:
  Authorization: Bearer <admin_token>
Request Body:
  {
    "reason": "Violating Terms of Service"
  }
```

#### ユーザーのトークンを全て失効
```
POST /api/admin/revoke-user-tokens/{user_id}/
Headers:
  Authorization: Bearer <admin_token>
```

#### ユーザー一覧（管理者）
```
GET /api/admin/users/?page=1&search=email
```

## 🏗️ プロジェクト構成

```
PyID/
├── config/                     # Django 設定
│   ├── settings.py            # メイン設定（環境変数対応）
│   ├── urls.py                # ルーティング
│   ├── wsgi.py                # WSGI 設定
│   └── asgi.py                # ASGI 設定
├── apps/
│   ├── accounts/              # ユーザー管理
│   │   ├── models.py          # User モデル
│   │   ├── serializers.py     # シリアライザー
│   │   ├── views.py           # ビュー
│   │   ├── admin.py           # 管理画面設定
│   │   └── migrations/
│   ├── oauth/                 # OAuth2/OIDC 実装
│   │   ├── models.py          # Authorization Code モデル
│   │   ├── views.py           # OAuth エンドポイント
│   │   ├── jwt_handler.py     # JWT 生成・検証
│   │   ├── serializers.py     # UserInfo シリアライザー
│   │   └── migrations/
│   └── admin_api/             # 管理者 API
│       ├── views.py           # 管理者エンドポイント
│       ├── permissions.py     # パーミッション
│       └── urls.py
├── core/                      # コア機能
│   ├── logging.py
│   └── exceptions.py
├── scripts/
│   └── create_superuser.py    # スーパーユーザー作成スクリプト
├── Dockerfile                 # Docker イメージ
├── docker-compose.yml         # Docker Compose 設定
├── requirements.txt           # Python 依存パッケージ
├── .env.example               # 環境変数テンプレート
├── .dockerignore
├── manage.py
└── README.md
```

## 🔐 セキュリティ機能

### BAN・即失効フロー

```
管理者: ユーザーをBAN
    ↓
User.ban() を実行
  - is_banned = True
  - force_logout_at = now()
  - banned_at = now()
    ↓
AccessToken/RefreshToken を無効化
  - revoked = True に更新
    ↓
全サービスで次のリクエスト時に Token 検証失敗
  - token.iat < force_logout_at
  - → Invalid Token
  - → ログイン画面へ
```

### JWT トークン検証

```
Token を受け取る
    ↓
署名検証（RS256）
    ↓
有効期限確認（exp）
    ↓
ユーザー状態確認
  - is_banned = False か確認
  - is_active = True か確認
  - token.iat < force_logout_at か確認
    ↓
✓ 全て OK → ユーザー情報返却
✗ NG → 403 エラー
```

## 📊 データモデル

### User
```
id (UUID)
email (unique)
username (unique)
password
email_verified (boolean)
email_verified_at (datetime)
is_active (boolean)
is_banned (boolean)
banned_at (datetime)
ban_reason (text)
force_logout_at (datetime)  # このタイムスタンプより前に発行されたトークンは無効
is_staff (boolean)
last_login_ip (IP address)
last_login_at (datetime)
login_count (integer)
created_at (datetime)
updated_at (datetime)
```

### UserAuditLog
```
id (UUID)
user (FK → User)
action (login, logout, password_change, email_verified, ban, unban, force_logout, oauth_token_issued, oauth_token_revoked)
ip_address (IP address)
user_agent (text)
details (JSON)
created_at (datetime)
```

### OAuthAuthorizationCode
```
id (UUID)
user (FK → User)
application (FK → oauth2_provider.Application)
code (unique)
redirect_uri (URL)
scope (text)
nonce (string, optional)
code_challenge (string)
code_challenge_method (plain or S256)
created_at (datetime)
```

## 🔧 開発

### ローカル開発サーバー起動

```bash
# 仮想環境を作成
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 依存パッケージをインストール
pip install -r requirements.txt

# DB マイグレーション
python manage.py migrate

# スーパーユーザーを作成
python manage.py createsuperuser

# 開発サーバーを起動
python manage.py runserver
```

### テスト実行

```bash
python manage.py test
```

### JWT 秘密鍵の生成（開発用）

```bash
# 秘密鍵・公開鍵を生成
mkdir -p certs
python -c "
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

with open('certs/private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('certs/public_key.pem', 'wb') as f:
    f.write(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print('✓ JWT key pair generated')
"
```

## 🌐 本番デプロイ

### 環境変数設定

```bash
# 本番用 .env
DEBUG=False
SECRET_KEY=<生成されたランダム文字列>
ALLOWED_HOSTS=sso.yourdomain.com

# HTTPS 強制
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True

# HSTS
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True
SECURE_HSTS_PRELOAD=True
```

### Nginx リバースプロキシ設定例

```nginx
upstream django_app {
    server django:8000;
}

server {
    listen 443 ssl http2;
    server_name sso.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/sso.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sso.yourdomain.com/privkey.pem;

    client_max_body_size 10M;

    location / {
        proxy_pass http://django_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /app/staticfiles/;
    }

    location /media/ {
        alias /app/media/;
    }
}
```

## 📈 本番環境での注意点

1. **SECRET_KEY の変更**
   - `settings.py` の SECRET_KEY は環境変数から読み込むこと
   - 強力なランダム文字列を生成すること

2. **HTTPS の強制**
   - 本番環境では必ず HTTPS を使用すること
   - HSTS ヘッダーを有効化すること

3. **Database バックアップ**
   - 定期的に PostgreSQL をバックアップすること
   - 特にユーザーデータは重要

4. **Redis の永続化**
   - `appendonly yes` で AOF を有効化すること
   - Token ブラックリストが失われないよう注意

5. **ログ監視**
   - Sentry や DataDog などでエラーを監視すること
   - 監査ログは定期的にレビューすること

6. **JWT 秘密鍵の管理**
   - 秘密鍵は `.env` ファイルまたは Kubernetes Secret で管理すること
   - 定期的なキーローテーションを実装することを推奨

## 📝 ライセンス

MIT License

## 👨‍💻 作成者

ゆんふぃ (@yunfie-twitter)
- Twitter: @yunfie_misskey
- Notes: https://notes.yunfie.org/

## 🤝 貢献

バグ報告や機能提案は Issue をお願いします。
Pull Request も歓迎です！
