### Mobile Endpoints

This App Used To Expose Some APIs As Endpoints To Used In Some Mobile Apps

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app $URL_OF_THIS_REPO --branch develop
bench install-app mobile_endpoints
```

### Pamper production configuration

The Web origin must be explicitly allowlisted in the site configuration. Native
Android and iOS requests do not require CORS.

```json
{
  "allow_cors": ["https://app.example.com"],
  "pamper_oauth_client_id": "<oauth-client-id>",
  "pamper_allow_legacy_api_key_login": true,
  "pamper_commission_rate": 5,
  "pamper_tax_rate": 15
}
```

Create an OAuth Client in Frappe with the exact Web, Android, and iOS callback
URIs used by the Pamper app. After the client completes its OAuth2 Authorization
Code + PKCE migration, set `pamper_allow_legacy_api_key_login` to `false` and
restart the site processes. Do not use `allow_cors: "*"` in production.

### Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/mobile_endpoints
pre-commit install
```

Pre-commit is configured to use the following tools for checking and formatting your code:

- ruff
- eslint
- prettier
- pyupgrade

### License

mit
