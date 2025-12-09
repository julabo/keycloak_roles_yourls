<?php
/*
Plugin Name: Restrict Keycloak Admin Access
Plugin URI: https://github.com/julabo/keycloak_roles_yourls
Description: Only users with the Keycloak role “Admin” are allowed to manage plugins. Debug shows tokens and roles.
Version: 1.0
Author: Jan Leehr
Author URI: https://julabo.com
*/

define('OIDC_REQUIRED_ROLE', 'Admin');

/**
 * Decodes the payload of a JWT (JSON Web Token).
 *
 * @param string $jwt The JWT string to decode.
 * @return array|null The decoded payload as an associative array, or null if decoding fails.
 */
function rpa_decode_jwt_payload(string $jwt): ?array
{
    $parts = explode('.', $jwt);
    if(count($parts) !== 3) return null;

    $payload = $parts[1];
    $payload = str_replace(['-', '_'], ['+', '/'], $payload);
    $payload .= str_repeat('=', 3 - (strlen($payload) + 3) % 4);
    $json = base64_decode($payload);
    if(!$json) return null;

    return json_decode($json, true);
}

/**
 * Checks if the currently authenticated user has the required role to access specific resources.
 * The function verifies the presence of an ID token in the session, decodes its payload,
 * and checks the roles assigned to the user against the required role.
 *
 * @return bool Returns true if the user has the required role, otherwise false.
 */
function rpa_user_has_required_role(): bool
{
    if (!isset($_SESSION)) session_start();

    if (!isset($_SESSION['oidc_id_token'])) {
        rpa_debug("No ID token present in the session.");
        return false;
    }

    $payload = rpa_decode_jwt_payload($_SESSION['oidc_id_token']);
    if (!$payload) {
        rpa_debug("ID token could not be decoded.");
        return false;
    }

    rpa_debug("Decoded ID-Token Payload:");
    rpa_debug($payload);

    if (isset($payload['resource_access']['yourls']['roles'])) {
        rpa_debug("resource_access.yourls.roles: " . implode(', ', $payload['resource_access']['yourls']['roles']));
        if (in_array(OIDC_REQUIRED_ROLE, $payload['resource_access']['yourls']['roles'])) {
            return true;
        }
    } else {
        rpa_debug("resource_access.yourls.roles: NONE");
    }

    return false;
}

/**
 * Outputs debugging information if debugging mode is enabled.
 * The function checks if debugging is turned on and formats the message for display.
 * It supports both scalar and complex data types such as arrays and objects for readability.
 *
 * @param mixed $msg The message or data to be output for debugging.
 * @return void
 */
function rpa_debug(mixed $msg): void
{
    if (defined('YOURLS_DEBUG') && YOURLS_DEBUG) {
        echo '<pre style="background:#eee;color:#000;padding:10px;">';
        if (is_array($msg) || is_object($msg)) {
            print_r($msg);
        } else {
            echo $msg;
        }
        echo '</pre>';
    }
}

/**
 * Checks if the user loads an admin page and restricts access to the plugin page if necessary.
 */
if (defined('YOURLS_ADMIN')) {
    $current_script = basename($_SERVER['PHP_SELF']);
    rpa_debug("Current script: $current_script");
    if ($current_script === 'plugins.php' && !rpa_user_has_required_role()) {
        yourls_die(
            'Access denied.',
            'You need the Keycloak role “Admin” to manage plugins.',
            ['status_code' => 403]
        );
    }

    // Remove the plugin menu item from the admin menu
    yourls_add_filter('admin_links', function($links) {
        if (!rpa_user_has_required_role()) {
            if (isset($links['plugins'])) {
                unset($links['plugins']);
            }
        }
        return $links;
    });
}
