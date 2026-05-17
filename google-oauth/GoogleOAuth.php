<?php

namespace PhPstrap\Modules\GoogleOAuth;

class GoogleOAuth
{
    private array $settings = [];
    private ?\PDO $pdo = null;

    const GOOGLE_AUTH_URL     = 'https://accounts.google.com/o/oauth2/v2/auth';
    const GOOGLE_TOKEN_URL    = 'https://oauth2.googleapis.com/token';
    const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

    public function init(): void
    {
        try {
            $this->pdo = getDbConnection();
            $stmt = $this->pdo->prepare(
                "SELECT settings FROM modules WHERE name = 'google-oauth' AND enabled = 1"
            );
            $stmt->execute();
            $module = $stmt->fetch();
            if ($module) {
                $this->settings = json_decode($module['settings'], true) ?? [];
            }
        } catch (\Exception $e) {
            error_log('GoogleOAuth init error: ' . $e->getMessage());
        }
    }

    public function isConfigured(): bool
    {
        return !empty($this->settings['client_id']) && !empty($this->settings['client_secret']);
    }

    public function getAuthUrl(): string
    {
        $state = bin2hex(random_bytes(16));
        $_SESSION['google_oauth_state'] = $state;

        return self::GOOGLE_AUTH_URL . '?' . http_build_query([
            'client_id'     => $this->settings['client_id'],
            'redirect_uri'  => $this->callbackUrl(),
            'response_type' => 'code',
            'scope'         => 'openid email profile',
            'state'         => $state,
            'access_type'   => 'online',
            'prompt'        => 'select_account',
        ]);
    }

    public function exchangeCode(string $code): ?array
    {
        $response = $this->post(self::GOOGLE_TOKEN_URL, [
            'code'          => $code,
            'client_id'     => $this->settings['client_id'],
            'client_secret' => $this->settings['client_secret'],
            'redirect_uri'  => $this->callbackUrl(),
            'grant_type'    => 'authorization_code',
        ]);

        return isset($response['access_token']) ? $response : null;
    }

    public function getUserInfo(string $access_token): ?array
    {
        $ch = curl_init(self::GOOGLE_USERINFO_URL);
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER     => ["Authorization: Bearer $access_token"],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $body      = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code !== 200 || !$body) {
            return null;
        }
        $data = json_decode($body, true);
        return isset($data['sub']) ? $data : null;
    }

    /**
     * Find an existing user by google_id or email, or create a new one.
     * Returns the user row on success, null if the domain is not allowed or
     * registration is disabled.
     */
    public function findOrCreateUser(array $google_user): ?array
    {
        if (!$this->isDomainAllowed($google_user['email'])) {
            return null;
        }

        // Prefer lookup by stable Google subject ID
        $stmt = $this->pdo->prepare(
            "SELECT * FROM users WHERE google_id = ? AND is_active = 1 LIMIT 1"
        );
        $stmt->execute([$google_user['sub']]);
        $user = $stmt->fetch();
        if ($user) {
            $this->updateLastLogin($user['id']);
            return $user;
        }

        // Link Google ID to an existing email account
        $stmt = $this->pdo->prepare(
            "SELECT * FROM users WHERE email = ? AND is_active = 1 LIMIT 1"
        );
        $stmt->execute([$google_user['email']]);
        $user = $stmt->fetch();
        if ($user) {
            $this->pdo->prepare("UPDATE users SET google_id = ?, verified = 1 WHERE id = ?")
                ->execute([$google_user['sub'], $user['id']]);
            $this->updateLastLogin($user['id']);
            $user['google_id'] = $google_user['sub'];
            return $user;
        }

        // New user — only if registration is open
        if (function_exists('getSetting') && getSetting('registration_enabled', '1') != '1') {
            return null;
        }

        $name         = trim($google_user['name'] ?? explode('@', $google_user['email'])[0]);
        $affiliate_id = substr(md5(uniqid((string)mt_rand(), true)), 0, 10);

        $stmt = $this->pdo->prepare(
            "INSERT INTO users (name, email, google_id, affiliate_id, verified, membership_status, is_active)
             VALUES (?, ?, ?, ?, 1, 'free', 1)"
        );
        $stmt->execute([$name, $google_user['email'], $google_user['sub'], $affiliate_id]);
        $user_id = (int)$this->pdo->lastInsertId();

        $this->updateLastLogin($user_id);

        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        return $stmt->fetch() ?: null;
    }

    public function createSession(array $user): void
    {
        $_SESSION['loggedin']           = true;
        $_SESSION['user_id']            = $user['id'];
        $_SESSION['name']               = $user['name'];
        $_SESSION['email']              = $user['email'];
        $_SESSION['membership_status']  = $user['membership_status'];
        $_SESSION['credits']            = $user['credits'] ?? 0;
        $_SESSION['is_admin']           = $user['is_admin'] ?? 0;
    }

    public function renderButton(string $text = 'Sign in with Google'): string
    {
        $auth_url = htmlspecialchars($this->getAuthUrl(), ENT_QUOTES, 'UTF-8');
        $label    = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');

        return <<<HTML
<a href="{$auth_url}" class="btn btn-google d-flex align-items-center justify-content-center gap-2 w-100">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="20" height="20" aria-hidden="true">
        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
        <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.36-8.16 2.36-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
    </svg>
    {$label}
</a>
HTML;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function callbackUrl(): string
    {
        $base = defined('BASE_URL') ? rtrim(BASE_URL, '/') : '';
        return $base . '/modules/google-oauth/callback.php';
    }

    private function isDomainAllowed(string $email): bool
    {
        $allowed = trim($this->settings['allowed_domains'] ?? '');
        if ($allowed === '') {
            return true;
        }
        $domain  = strtolower(substr(strrchr($email, '@'), 1));
        $domains = array_map('trim', explode(',', strtolower($allowed)));
        return in_array($domain, $domains, true);
    }

    private function updateLastLogin(int $user_id): void
    {
        $ip = function_exists('getUserIP') ? getUserIP() : ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $this->pdo->prepare(
            "UPDATE users SET last_login_at = NOW(), last_login_ip = ?, login_attempts = 0 WHERE id = ?"
        )->execute([$ip, $user_id]);
    }

    private function post(string $url, array $fields): ?array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($fields),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $body      = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code !== 200 || !$body) {
            return null;
        }
        return json_decode($body, true) ?: null;
    }
}
