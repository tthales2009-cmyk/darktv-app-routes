# DarkTV signed route configuration

This public repository distributes a signed configuration document. It must contain only public HTTPS destinations and public verification material. Credentials and private signing keys never belong here.

CI verifies the current document with the same public RSA key used by the Cinema apps, rejects credential-bearing destinations, and tests tampering and malformed envelopes. It does not sign, modify, deploy or announce routes and needs no secrets or npm dependencies.

Run `node --test tests/routes.test.cjs` and `node scripts/verify-routes.cjs` with Node24. Keep JSON property order: the signature covers the serialized payload used by the apps. Signing-key rotation requires a separate coordinated change with the clients; replacing this verification key alone does not update installed apps.
