<?php
/**
 * Google OAuth 2.0 callback handler.
 * Google redirects here after the user grants (or denies) access.
 */

require_once '../../config/app.php';
require_once '../../config/functions.php';
initializeApp();

// Already logged in — go to dashboard
if (function_exists('isLoggedIn') && isLoggedIn()) {
    redirect(rtrim(BASE_URL, '/') . '/dashboard/');
}

$error = null;

do {
    // User denied access
    if (!empty($_GET['error'])) {
        $error = 'Google sign-in was cancelled.';
        break;
    }

    $code  = $_GET['code']  ?? '';
    $state = $_GET['state'] ?? '';

    if (empty($code) || empty($state)) {
        $error = 'Invalid OAuth response.';
        break;
    }

    // CSRF check
    if (!hash_equals($_SESSION['google_oauth_state'] ?? '', $state)) {
        $error = 'State mismatch — please try again.';
        break;
    }
    unset($_SESSION['google_oauth_state']);

    // Load module
    $module_file = __DIR__ . '/GoogleOAuth.php';
    if (!file_exists($module_file)) {
        $error = 'Google OAuth module files are missing.';
        break;
    }
    require_once $module_file;

    try {
        $pdo = getDbConnection();
        $stmt = $pdo->prepare(
            "SELECT enabled, settings FROM modules WHERE name = 'google-oauth'"
        );
        $stmt->execute();
        $module_row = $stmt->fetch();

        if (!$module_row || !$module_row['enabled']) {
            $error = 'Google sign-in is not enabled.';
            break;
        }

        $oauth = new PhPstrap\Modules\GoogleOAuth\GoogleOAuth();
        $oauth->init();

        if (!$oauth->isConfigured()) {
            $error = 'Google sign-in is not configured.';
            break;
        }

        // Exchange authorization code for tokens
        $tokens = $oauth->exchangeCode($code);
        if (!$tokens) {
            $error = 'Failed to exchange authorization code. Please try again.';
            break;
        }

        // Fetch Google user profile
        $google_user = $oauth->getUserInfo($tokens['access_token']);
        if (!$google_user || empty($google_user['email'])) {
            $error = 'Could not retrieve your Google profile. Please try again.';
            break;
        }

        // Find or register user
        $user = $oauth->findOrCreateUser($google_user);
        if (!$user) {
            $error = 'Sign-in failed — your email domain may not be permitted, or new registrations are closed.';
            break;
        }

        // Start session
        $oauth->createSession($user);

        $destination = $user['is_admin']
            ? rtrim(BASE_URL, '/') . '/admin/'
            : rtrim(BASE_URL, '/') . '/dashboard/';

        redirect($destination);

    } catch (\Exception $e) {
        error_log('GoogleOAuth callback error: ' . $e->getMessage());
        $error = 'An unexpected error occurred. Please try again.';
    }
} while (false);

// Error path — redirect to login with a message
if ($error) {
    $_SESSION['login_error'] = $error;
    redirect(rtrim(BASE_URL, '/') . '/login/');
}
