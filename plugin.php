<?php
/*
Plugin Name: Restrict Keycloak Admin Access
Plugin URI: https://github.com/julabo/keycloak_roles_yourls
Description: Only users with the Keycloak role "Admin" are allowed to manage plugins. Debug shows tokens and roles.
Version: 1.1.1
Author: Jan Leehr
Author URI: https://julabo.com
*/

if (!defined('OIDC_ADMIN_ROLE')) {
    define('OIDC_ADMIN_ROLE', 'Admin');
}

if (!defined('OIDC_USER_ROLE')) {
    define('OIDC_USER_ROLE', 'User');
}

// Load the main plugin class
require_once __DIR__ . '/KeycloakRoleAccess.php';

// Initialize the plugin
new KeycloakRoleAccess();
