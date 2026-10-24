# @riao/authn-fido2

This implementation provides FIDO2/WebAuthn registration and authentication using the SimpleWebAuthn library, with database-backed credential and challenge storage.

## Table of Contents

- [Overview](#overview)
- [Database Schema](#database-schema)
- [API Reference](#api-reference)
- [Authentication Flows](#authentication-flows)
- [Usage Examples](#usage-examples)  
- [Security Considerations](#security-considerations)
- [Testing](#testing)

## Overview

This FIDO2 implementation provides passwordless authentication using WebAuthn standards. It supports:

- **Biometric Authentication**: Fingerprint, Face ID, Windows Hello
- **Hardware Security Keys**: YubiKey, Titan Security Keys
- **Platform Authenticators**: Built-in device authenticators
- **Multi-Device Support**: Multiple credentials per user
- **Cross-Platform Compatibility**: Works across browsers and platforms

### Key Features

- ✅ Complete WebAuthn registration and authentication flows
- ✅ Database-backed challenge and credential storage
- ✅ Multi-credential support per principal
- ✅ Integration with riao framework
- ✅ Type-safe TypeScript implementation
- ✅ Comprehensive test coverage

## Installation

```bash
npm install @riao/authn-fido2 @riao/iam @riao/dbal
npm install --save-dev @riao/cli
```

### Database Migrations

```bash
npx riao migration:create import-fido2-tables
```

`database/main/migrations/123456789-import-fido2-tables.ts`
```typescript
import { AuthenticationFido2Migrations } from '@riao/authn-fido2/authentication-fido2-migrations';

export default AuthenticationFido2Migrations;
```


## Core Components

1. **Fido2Authentication Class**: Main authentication handler
2. **Database Schema**: Two tables for challenges and credentials  
3. **SimpleWebAuthn Integration**: Industry-standard WebAuthn library
4. **Challenge Management**: Challenge storage and used-state updates
5. **Credential Repository**: Persistent authenticator credential storage

## Database Schema

The implementation uses two tables for managing the FIDO2 authentication lifecycle:

### fido2_challenges

Stores challenge records during registration/authentication flows. Generated
challenges include an `expires` timestamp five minutes after creation, but the
driver does not check that timestamp during verification or automatically
remove expired rows. Applications must enforce any required challenge-expiry
policy and clean up old rows. Challenges are marked used after successful
verification, but concurrent verification attempts are not atomically
serialized.

### fido2_credentials

Stores persistent authenticator credentials

## API Reference

### Configuration
The `Fido2Authentication` class requires configuration for your Relying Party (RP) information and database connection:

- **`rpName`**: Your application name (shown to users)
- **`rpID`**: Your domain (must match the origin domain)  
- **`origin`**: Your application URL (must be HTTPS in production)
- **`repo`**: Principal repository for user management
- **`db`**: Database instance for challenge/credential storage

> 🔍 **Type Definitions**: See [`Fido2AuthenticationOptions`](./src/authentication-fido2.ts) interface for complete configuration options.

### Core Methods

The implementation provides methods for the complete FIDO2 lifecycle:

#### Registration Flow
- **`generateRegistrationOptions(principal)`**: Creates WebAuthn registration options and stores challenge
- **`verifyRegistration(principal, response)`**: Verifies WebAuthn response and stores credential

#### Authentication Flow  
- **`generateAuthenticationOptions(userID?)`**: Creates authentication challenge (with or without specific user)
- **`authenticate(credentials)`**: Verifies authentication response and returns principal

#### Principal Management
- **`createPrincipal(principal)`**: Creates user and auto-generates registration challenge

> 📚 **Method Details**: See the [class implementation](./src/authentication-fido2.ts)

## Authentication Flows

### Registration Flow

Enroll a new authenticator (fingerprint, security key, etc.) for a user .

**Steps**:
1. **Generate Options**: Server creates registration challenge and WebAuthn options
2. **Client Registration**: Browser/app prompts user for biometric/PIN and creates credential  
3. **Verify Registration**: Server validates the response and stores credential

```typescript
// 1. Server generates options
const options = await auth.generateRegistrationOptions(principal);

// 2. Client creates credential (browser WebAuthn API)  
const credential = await navigator.credentials.create({ publicKey: options });

// 3. Server verifies and stores
const result = await auth.verifyRegistration(principal, credential);
```

### Authentication Flow

Authenticate a user using an existing credential (passwordless login)

**Steps**:
1. **Generate Challenge**: Server creates authentication challenge (optionally for specific user)
2. **Client Authentication**: Browser/app prompts for biometric/PIN to sign challenge
3. **Verify Authentication**: Server validates signature and returns authenticated user

```typescript
// 1. Server generates challenge  
const options = await auth.generateAuthenticationOptions(userID);

// 2. Client signs challenge (browser WebAuthn API)
const assertion = await navigator.credentials.get({ publicKey: options });

// 3. Server verifies signature
const principal = await auth.authenticate({ response: assertion, principalId: userID });
if (principal !== null) {
  // Create your application's session for principal.id.
} else {
  // Return a generic login rejection, including blocked attempts.
}
```

### Version 3 Authentication Contract

Requires `@riao/iam` 5. Options extend IAM's `AuthenticationOptions`, including
`authenticationProtection`. `authenticate()` runs `beforeAttempt`, then
`onFailure` for ordinary invalid credentials or `onSuccess` only for a verified
active principal. Denied attempts return `null` without failure/success hooks.
Missing or used challenges, unknown credentials, inactive
principals, verifier `verified: false`, and known SimpleWebAuthn assertion
validation errors return `null`. Failure/success subjects are principal
IDs, and assertion secrets are never passed to the protection hooks.

IAM 5's lock entry omits registry `resolved`/`integrity` until publication.
Regenerate with `npm install --package-lock-only` after release to record
registry integrity.

SimpleWebAuthn 13 reports several validation failures as plain `Error`s. The
driver recognizes a narrow, tested set of its messages; unknown verifier
exceptions (including crypto/service outages) propagate, as do database and
protection-hook exceptions. Malformed client JSON is rejected separately at
the untrusted input boundary. Do not count operational errors as bad credentials.

Counter persistence errors propagate without failure/success hooks.
Success-hook outages likewise propagate
after persistence, without reclassifying the attempt as invalid credentials.
Supply a known principal ID when
generating options: options generated without one have no stored challenge
and cannot currently complete this principal-bound authentication flow.

Authentication returns a trusted principal, not an application session or
bearer token. Create an application-owned session only on non-null success.
Use generic rejection responses at HTTP boundaries and handle operational
errors separately (for example HTTP 503). `null` does not carry a retry delay;
exchange APIs that throw IAM's `AuthenticationBlockedError` may map its
optional `retryAfterSeconds` to `Retry-After` and HTTP 429.

## Usage Examples

### Basic Setup

```typescript
import { Fido2Authentication } from '@riao/authn-fido2';

// Configure for your application
const fido2Auth = new Fido2Authentication({
  db,                         // RIAO database instance
  rpName: 'My App',          // Shown to users during registration
  rpID: 'myapp.com',         // Your domain
  origin: 'https://myapp.com' // Your app URL (HTTPS in prod)
});
```

> 💡 **Complete Examples**: See the [test file](./test/spec/authentication-fido2.spec.ts) for comprehensive usage examples, including Express.js integration patterns and client-side WebAuthn code.

### Integration Patterns

**Server-Side**: Create REST endpoints for `/register/begin`, `/register/finish`, `/authenticate/begin`, `/authenticate/finish`  
**Client-Side**: Use browser WebAuthn API (`navigator.credentials.create()` and `navigator.credentials.get()`)  
**Data Flow**: JSON serialization with proper Base64 encoding for binary data

## Security Considerations

### Challenge Management

- **Expiration metadata**: Challenges are assigned an `expires` timestamp five
  minutes after creation, but the driver does not enforce it
- **Used state**: Successfully verified challenges are marked used; the driver
  does not guarantee atomic single-use behavior for concurrent attempts
- **Cryptographic Security**: Challenges are generated by SimpleWebAuthn with proper entropy

### Credential Storage

- **Counter Protection**: Authenticator counters prevent replay attacks
- **Public Key Security**: Only public keys are stored, never private keys
- **Cascade Deletion**: Credentials are automatically cleaned up when principals are deleted

### Transport Security

- **HTTPS Required**: WebAuthn requires secure contexts (HTTPS in production)
- **Origin Validation**: Strict origin checking prevents credential theft
- **Cross-Origin Protection**: Credentials are bound to specific domains

### Best Practices

1. **Always use HTTPS** in production environments
2. **Validate origins** strictly to prevent phishing attacks
3. **Implement rate limiting** on authentication endpoints
4. **Enforce challenge expiry and cleanup** in your application if required
5. **Use secure session management** after successful authentication
6. **Implement proper error handling** without revealing sensitive information

### Attack Mitigation

- **Replay Attacks**: Prevented by counter validation
- **Phishing**: Prevented by origin binding and cryptographic verification
- **Man-in-the-Middle**: Prevented by HTTPS and challenge-response protocol
- **Credential Theft**: Impossible - only public keys are stored
- **Brute Force**: Not applicable - uses cryptographic proofs


## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!
