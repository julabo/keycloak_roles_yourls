# Keycloak Roles YOURLS Plugin

A YOURLS plugin that restricts administrative access based on Keycloak roles.
Only users with the "Admin" role in Keycloak are allowed to manage plugins in the YOURLS admin interface.

## Features

- **Role-based Access Control**: Restricts plugin management to users with the Keycloak "Admin" role
- **JWT Token Validation**: Decodes and validates Keycloak ID tokens from user sessions
- **Admin Menu Control**: Dynamically removes plugin menu items for unauthorized users
- **Debug Support**: Comprehensive debugging output when YOURLS debug mode is enabled
- **Session Integration**: Works seamlessly with existing OIDC/Keycloak authentication

## Requirements

- YOURLS URL shortener
- Keycloak server with OIDC authentication configured
- PHP 7.4.0 or higher
- Active PHP session with Keycloak ID tokens

## Installation

1. Download or clone this repository to your YOURLS plugins directory:
   ```bash
   cd /path/to/yourls/user/plugins/
   git clone https://github.com/julabo/keycloak_roles_yourls.git
   ```

2. Activate the plugin through the YOURLS admin interface or by adding it to your configuration.

## Configuration

The plugin uses the following constants that can be customized:

- `OIDC_REQUIRED_ROLE`: The Keycloak role required for admin access (default: "Admin")

To change the required role, modify this line in `plugin.php`:

```php
define('OIDC_REQUIRED_ROLE', 'YourCustomRole');
```

## How It Works

1. **Token Validation**: The plugin checks for the presence of `oidc_id_token` in the user's session
2. **JWT Decoding**: Decodes the JWT payload to extract user roles
3. **Role Verification**: Checks if the user has the required role in `resource_access.yourls.roles`
4. **Access Control**: Blocks access to `plugins.php` and removes plugin menu items for unauthorized users

## Debugging

Enable YOURLS debug mode to see detailed token and role information:

```php
php define('YOURLS_DEBUG', true);
```

This will display:
- Current script being accessed
- Decoded ID token payload
- User roles from Keycloak
- Access control decisions

## Security Features

- **403 Forbidden Response**: Unauthorized access attempts return proper HTTP status codes
- **Menu Item Removal**: Plugin management links are hidden from unauthorized users
- **Session-based Validation**: Relies on server-side session data, not client-side tokens

## Keycloak Configuration

Ensure your Keycloak client is configured to:
1. Include the "yourls" resource in the access token
2. Assign appropriate roles to users under the "yourls" client scope
3. Configure OIDC authentication for your YOURLS instance

## Error Handling

The plugin gracefully handles:
- Missing or invalid JWT tokens
- Malformed token payloads
- Missing role information
- Session initialization issues

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for full license text.

## Support

For issues, feature requests, or contributions, please visit the [GitHub repository](https://github.com/julabo/keycloak_roles_yourls).
