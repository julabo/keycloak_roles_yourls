<?php

use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

/**
 * Main plugin class for Keycloak role-based access control
 */
class KeycloakRoleAccess
{
    private const REQUIRED_ROLES = [OIDC_ADMIN_ROLE, OIDC_USER_ROLE];
    private ?array $userRoles = null;
    private bool $debugMode;

    public function __construct()
    {
        $this->debugMode = defined('YOURLS_DEBUG') && YOURLS_DEBUG;
        $this->initializeAdminRestrictions();
    }

    /**
     * Initialize admin page restrictions
     */
    private function initializeAdminRestrictions(): void
    {
        if (!defined('YOURLS_ADMIN')) {
            return;
        }

        // Check if user is logged in and has required roles
        if ($this->isUserLoggedIn()) {
            if (!$this->userHasRequiredRole()) {
                $this->denyAccess('You do not have access to this resource.');
            }
        }

        $this->restrictPluginAccess();
        $this->filterAdminMenu();
    }

    /**
     * Check if user is logged in (has valid session with ID token)
     */
    public function isUserLoggedIn(): bool
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        $isLoggedIn = isset($_SESSION['oidc_id_token']) && !empty($_SESSION['oidc_id_token']);
        $this->debug("User logged in: " . ($isLoggedIn ? 'Yes' : 'No'));

        return $isLoggedIn;
    }

    /**
     * Checks if the current user has any of the required roles
     */
    public function userHasRequiredRole(): bool
    {
        // If user is not logged in, they don't have required roles
        if (!$this->isUserLoggedIn()) {
            $this->debug("User not logged in - no required role");
            return false;
        }

        $userRoles = $this->getUserRoles();

        // If user has no roles at all, deny access
        if (empty($userRoles)) {
            $this->debug("User is logged in but has no roles assigned");
            return false;
        }

        $hasRequiredRole = !empty(array_intersect(self::REQUIRED_ROLES, $userRoles));
        $this->debug("User roles: " . implode(', ', $userRoles));
        $this->debug("Required roles: " . implode(', ', self::REQUIRED_ROLES));
        $this->debug("Has required role: " . ($hasRequiredRole ? 'Yes' : 'No'));

        return $hasRequiredRole;
    }

    /**
     * Get user roles from cache, live from Keycloak tokens, or JWT token fallback
     */
    private function getUserRoles(): array
    {
        if ($this->userRoles !== null) {
            return $this->userRoles;
        }

        $this->userRoles = [];

        if (!$this->isUserLoggedIn()) {
            return $this->userRoles;
        }

        // Debug token expiration
        $this->debugTokenStatus();

        // Try to refresh token if needed
        $this->refreshTokenIfNeeded();

        // Try access token for roles
        $accessTokenRoles = $this->getRolesFromAccessToken();
        $this->debug($accessTokenRoles);
        if (!empty($accessTokenRoles)) {
            $this->userRoles = $accessTokenRoles;
            $this->debug("Roles from access token: " . implode(', ', $this->userRoles));
            return $this->userRoles;
        }

        return $this->userRoles;
    }

    /**
     * Debug token status and expiration
     */
    private function debugTokenStatus(): void
    {
        if (!$this->debugMode) {
            return;
        }

        $expires_at = $_SESSION['oidc_token_expires_at'] ?? 0;
        $current_time = time();

        $this->debug("=== TOKEN STATUS DEBUG ===");
        $this->debug("Current time: " . date('Y-m-d H:i:s', $current_time));
        $this->debug("Token expires at: " . ($expires_at ? date('Y-m-d H:i:s', $expires_at) : 'Not set'));
        $this->debug("Time until expiry: " . ($expires_at - $current_time) . " seconds");
        $this->debug("Has access token: " . (isset($_SESSION['oidc_access_token']) ? 'Yes' : 'No'));
        $this->debug("Has refresh token: " . (isset($_SESSION['oidc_refresh_token']) ? 'Yes' : 'No'));

        // Try to decode access token to see its expiration
        if (isset($_SESSION['oidc_access_token'])) {
            $accessTokenPayload = $this->decodeJwtPayload($_SESSION['oidc_access_token']);
            if ($accessTokenPayload && isset($accessTokenPayload['exp'])) {
                $tokenExp = $accessTokenPayload['exp'];
                $this->debug("Access token internal expiry: " . date('Y-m-d H:i:s', $tokenExp));
                $this->debug("Token internally expires in: " . ($tokenExp - $current_time) . " seconds");
            }
        }
        $this->debug("=== END TOKEN STATUS ===");
    }

    /**
     * Refresh token if needed
     */
    private function refreshTokenIfNeeded(): void
    {
        // Skip if tokens not available
        if (!isset($_SESSION['oidc_access_token']) || !isset($_SESSION['oidc_refresh_token'])) {
            $this->debug("Tokens not available for refresh");
            return;
        }

        $expires_at = $_SESSION['oidc_token_expires_at'] ?? 0;
        $refreshThreshold = defined('OIDC_TOKEN_REFRESH_THRESHOLD') ? OIDC_TOKEN_REFRESH_THRESHOLD : 300;
        $refresh_time = time() + $refreshThreshold;

        // Token still valid
        if ($expires_at > $refresh_time) {
            $this->debug("Token still valid, no refresh needed");
            return;
        }

        $this->debug("Token needs refresh, attempting to refresh...");

        try {
            $provider = $this->getOidcProvider();
            if (!$provider) {
                $this->debug("Could not get OIDC provider for token refresh");
                return;
            }

            $refreshToken = new AccessToken([
                'access_token' => $_SESSION['oidc_access_token'],
                'refresh_token' => $_SESSION['oidc_refresh_token'],
                'expires' => $expires_at
            ]);

            $newToken = $provider->getAccessToken('refresh_token', [
                'refresh_token' => $refreshToken->getRefreshToken()
            ]);

            // Update session with new tokens
            $_SESSION['oidc_access_token'] = $newToken->getToken();
            $_SESSION['oidc_token_expires_at'] = $newToken->getExpires();

            if ($newToken->getRefreshToken()) {
                $_SESSION['oidc_refresh_token'] = $newToken->getRefreshToken();
            }

            // Clear roles cache to force fresh fetch
            unset($_SESSION['oidc_roles_cache']);
            unset($_SESSION['oidc_roles_cache_time']);

            $this->debug("Token successfully refreshed");

        } catch (Exception $e) {
            $this->debug("Token refresh failed: " . $e->getMessage());
            error_log('Token refresh failed: ' . $e->getMessage());

            // Clear invalid tokens
            unset($_SESSION['oidc_access_token']);
            unset($_SESSION['oidc_refresh_token']);
            unset($_SESSION['oidc_token_expires_at']);
        }
    }

    /**
     * Get OIDC provider instance
     */
    private function getOidcProvider(): ?Keycloak
    {
        try {
            return new Keycloak([
                'authServerUrl' => rtrim($this->getKeycloakConfig('BASE_URL'), '/'),
                'realm' => $this->getKeycloakConfig('REALM'),
                'clientId' => $this->getKeycloakConfig('CLIENT_NAME'),
                'clientSecret' => $this->getKeycloakConfig('CLIENT_SECRET'),
                'redirectUri' => $this->getKeycloakConfig('REDIRECT_URL'),
            ]);
        } catch (Exception $e) {
            $this->debug('OIDC provider initialization error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get roles from the access token directly
     */
    private function getRolesFromAccessToken(): ?array
    {
        if (!isset($_SESSION['oidc_access_token'])) {
            $this->debug("No access token available");
            return null;
        }

        $payload = $this->decodeJwtPayload($_SESSION['oidc_access_token']);
        if (!$payload) {
            $this->debug("Access token could not be decoded");
            return null;
        }

        $this->debug("Decoded Access Token Payload:");
        $this->debug($payload);

        return $payload['resource_access']['yourls']['roles'] ?? null;
    }

    /**
     * Get Keycloak configuration value
     */
    private function getKeycloakConfig(string $key): ?string
    {
        $envKey = 'OIDC_' . $key;
        $constKey = 'OIDC_' . $key;

        $value = getenv($envKey) ?: ($_ENV[$envKey] ?? null);

        if ($value === null && defined($constKey)) {
            $value = constant($constKey);
        }

        return $value ?: null;
    }

    /**
     * Decode JWT payload with proper error handling
     */
    private function decodeJwtPayload(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            $this->debug("Invalid JWT format");
            return null;
        }

        $payload = $this->base64UrlDecode($parts[1]);
        if (!$payload) {
            $this->debug("Failed to decode JWT payload");
            return null;
        }

        $decoded = json_decode($payload, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->debug("JSON decode error: " . json_last_error_msg());
            return null;
        }

        return $decoded;
    }

    /**
     * Base64 URL decode with padding fix
     */
    private function base64UrlDecode(string $data): string|false
    {
        $data = str_replace(['-', '_'], ['+', '/'], $data);
        $data .= str_repeat('=', 3 - (strlen($data) + 3) % 4);
        return base64_decode($data);
    }

    /**
     * Restrict access to the plugin management page
     */
    private function restrictPluginAccess(): void
    {
        $currentScript = basename($_SERVER['PHP_SELF']);
        $this->debug("Current script: $currentScript");

        // Only restrict if the user is logged in but lacks an admin role
        if ($currentScript === 'plugins.php' &&
            $this->isUserLoggedIn() &&
            !$this->userHasAdminRole()) {
            $this->denyAccess('You need the Keycloak role "Admin" to manage plugins.');
        }
    }

    /**
     * Remove plugin menu item from admin menu for unauthorized logged-in users
     */
    private function filterAdminMenu(): void
    {
        yourls_add_filter('admin_links', function($links) {
            // Only hide the menu if user is logged in but lacks an admin role
            if ($this->isUserLoggedIn() && !$this->userHasAdminRole()) {
                unset($links['plugins']);
            }
            return $links;
        });
    }

    /**
     * Check if the current user has the Admin role specifically
     */
    private function userHasAdminRole(): bool
    {
        if (!$this->isUserLoggedIn()) {
            $this->debug("User not logged in - no admin role");
            return false;
        }

        $userRoles = $this->getUserRoles();

        if (empty($userRoles)) {
            $this->debug("User is logged in but has no roles assigned");
            return false;
        }

        $hasAdminRole = in_array(OIDC_ADMIN_ROLE, $userRoles);
        $this->debug("User roles: " . implode(', ', $userRoles));
        $this->debug("Admin role required: " . OIDC_ADMIN_ROLE);
        $this->debug("Has admin role: " . ($hasAdminRole ? 'Yes' : 'No'));

        return $hasAdminRole;
    }

    /**
     * Deny access and terminate execution
     */
    private function denyAccess(string $message = 'You have no access to this resource.'): void
    {
        yourls_die(
            'Access denied.',
            $message,
            ['status_code' => 403]
        );
    }

    /**
     * Debug output helper
     */
    private function debug(mixed $message): void
    {
        if (!$this->debugMode) {
            return;
        }

        echo '<pre style="background:#eee;color:#000;padding:10px;margin:5px 0;">';
        if (is_array($message) || is_object($message)) {
            print_r($message);
        } else {
            echo htmlspecialchars((string)$message);
        }
        echo '</pre>';
    }
}
