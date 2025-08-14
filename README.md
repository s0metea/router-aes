# Burp Suite AES‑CBC Auto Decrypter + Request Plaintext Capture (Montoya)

A Burp Suite extension (Montoya API) that makes working with AES‑CBC/PKCS7 encrypted APIs painless.

It automatically:
- Decrypts server responses shaped like `{ "content": "...", "iv": "..." }` using your configured AES key.
- Injects a lightweight hook (hook.js) into the app’s `/static/js/app.js` so we can capture plaintext requests before the browser encrypts them.
- Correlates captured plaintext to the matching encrypted request using the IV and shows the plaintext in the UI.
- Optionally encrypts Repeater requests for you (AES‑CBC/PKCS7), with an RSA‑wrapped AES key where required.

This was designed for router/admin web UIs that use AES‑CBC with an RSA key exchange pattern.


## Why and how

Typical flows we target look like this:
- Outgoing requests from the browser are AES‑CBC encrypted on the client. Burp cannot decrypt them because it does not know the ephemeral AES key used by the client. To show plaintext, we inject `hook.js` that wraps the app’s encrypt function (e.g., `AesRsaEncrypt`) and sends a small beacon to `/__capture__` with the plaintext and IV right before encryption.
- Incoming responses from the server are also AES‑CBC encrypted but use a static/shared key (or a key you already know). The plugin decrypts these using the AES key you configure in the UI.

Key design principles:
- IV is used only as a correlation handle between a captured plaintext beacon and the encrypted request we see in Burp. We do not use IV to retrieve any decryption key for responses.
- We never try to decrypt client requests with the configured AES key. Requests are shown in plaintext strictly from the capture hook.
- All `__/capture__` beacons are dropped and not listed in the table to avoid noise; they are only used to update the associated request row.


## Features

- Target origin filter: only traffic matching your origin is processed.
- Automatic response decryption for envelopes like:
  - `{ "content": "<Base64 AES-CBC>", "iv": "<Base64 or Hex>" }`
- Robust Base64 handling (includes base64url and common JSON escape unescaping) and IV parsing from Base64 or Hex (normalized to 16 bytes).
- Hook injection into `/static/js/app.js` to capture plaintext requests before encryption.
- IV‑based correlation to update the request pane with plaintext once the beacon arrives.
- Optional Repeater encryption: POST/PUT/PATCH bodies are wrapped into the encrypted JSON envelope. For POST `/UserLogin` (or when set to "always set"), the AES key is RSA‑encrypted and placed in the `key` field.
- Auto‑populate RSA public key from `GET /getRSAPublickKey` response:
  ```json
  {"RSAPublicKey":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n","result":"ZCFG_SUCCESS"}
  ```
- Clean response shaping: only the body is replaced; `Content-Encoding` and `Content-Length` are removed to avoid mismatches.
- Side‑by‑side HTTP request and response viewers with a table of intercepted items.


## Installation / Build

Requirements:
- Burp Suite (Montoya API). Burp 2023+ runs on Java 17; using JDK 17+ is recommended.

Build with the included Gradle wrapper:
- macOS/Linux:
  - `sh ExtensionTemplateProject/gradlew -p ExtensionTemplateProject clean build -x test`
- Windows (PowerShell/CMD):
  - `ExtensionTemplateProject\gradlew.bat -p ExtensionTemplateProject clean build -x test`

The JAR will be at:
- `ExtensionTemplateProject/build/libs/extension-template-project.jar`

Load it into Burp:
- Burp -> Extensions -> Installed -> Add -> Select the JAR -> Confirm.
- The extension tab appears as "AES Decrypt".


## Configuration & UI

Top controls (left to right):
- Target origin: e.g. `https://router.local` or `router.local`. Only matching traffic is processed.
- Enabled: master switch for decryption logic.
- AES key: The key used to decrypt responses and to encrypt Repeater requests.
  - Accepted formats: Base64, Hex, or raw UTF‑8 text (fallback).
- Encrypt Repeater requests: When enabled, POST/PUT/PATCH requests from Repeater will be encrypted.
- IV: IV to use when encrypting from Repeater. Accepted as Base64 or Hex.
- Key parameter mode: Controls the `key` field in the encrypted request JSON when sending from Repeater:
  - "only on POST /UserLogin": `key` is RSA‑encrypted AES key only for POST `/UserLogin`; otherwise `"key":""`.
  - "always set": `key` is populated for all POST/PUT/PATCH.
- RSA Public Key: PEM field. This is auto‑filled on `GET /getRSAPublickKey`, but you can paste it manually.

Table and Editors:
- The table shows: Time, Method, URL, Status, Decrypted (flag), and Note.
- Selecting a row shows the request (left) and response (right) simultaneously.
- Request pane: shows the captured plaintext body if available; otherwise the original body.
- Response pane: shows the decrypted plaintext body for supported responses.


## How it works in detail

1) Hook injection
- Every response for `/static/js/app.js` gets `hook.js` appended. The hook tries to locate a component with `AesRsaEncrypt` (Vue 2 or Vue 3) and wraps it.
- When the app encrypts a request, the hook sends a beacon to `/__capture__` with fields like:
  - `ivB64`, `plaintext`, `plaintextPreview`, `aesKeyB64` (if visible to the function), and a small diagnostic block.

2) Capture handling
- The extension intercepts all `POST /__capture__` beacons (or `GET /__capture__?d=...`).
- It extracts the JSON payload, finds `iv`/`ivB64`, and looks up the matching encrypted request row using the IV.
- It updates that row’s request pane with the captured plaintext.
- The capture request is dropped and not shown in the table.

3) Response decryption
- For JSON responses containing `content` and `iv`, the AES key from the UI and the IV in the JSON are used to decrypt via AES‑CBC/PKCS7.
- The decrypted response body replaces the original; `Content-Length` and `Content-Encoding` headers are removed. Other headers remain unchanged.

4) Repeater encryption
- When enabled, Repeater’s POST/PUT/PATCH request bodies are encrypted and replaced with JSON like:
  ```json
  {
    "content": "<Base64 ciphertext>",
    "key": "<RSA-encrypted AES key or empty string>",
    "iv": "<Base64 IV>"
  }
  ```
- For POST `/UserLogin`, or when mode is "always set", the `key` field is the RSA‑encrypted AES key using the configured RSA public key.
- For other methods/endpoints in "only on POST /UserLogin" mode, the `key` field is an empty string.


## Supported encrypted envelope

- Requests (from the app) and responses (from the server) typically use:
  ```json
  { "content": "<Base64 AES-CBC>", "iv": "<Base64 or Hex>" }
  ```
- Base64url variants are supported; common JSON escaping (like `\/` or unicode escapes for `+`/`/`/`=`) is normalized internally.


## Example

- A decrypted response might look like a plain JSON object with device info; only the body changes, headers remain (minus `Content-Length`/`Content-Encoding`).
- A properly encrypted Repeater request for `/UserLogin` will contain all three fields: `content`, `key`, and `iv`.


## Troubleshooting

- "decrypt error":
  - Verify the AES key and IV format. AES key can be Base64/Hex/UTF‑8; IV must be Base64 or Hex (normalized to 16 bytes). Ensure the response body really contains `content` and `iv`.
  - Some servers escape Base64; the extension normalizes most variants, but check for typos or truncated data.
- No plaintext requests appear:
  - Ensure `/static/js/app.js` is actually loaded by the app and not cached; try hard refresh (Shift+Reload) so the injected hook is executed.
  - The function name must be `AesRsaEncrypt` for auto‑hooking. If the app uses a different name, consider adapting `hook.js` in the source.
  - Make sure your origin filter matches the actual URL in Burp so items are processed and displayed.
- RSA key is empty during Repeater encryption:
  - Either paste the PEM into the RSA field or visit the `GET /getRSAPublickKey` endpoint while the extension is enabled to auto‑populate.
- Capture beacons blocked:
  - Some strict CSPs or client behavior can block `sendBeacon`/`fetch` from the hook. The hook falls back to an `<img>` GET with base64 payload (`d=` param). Ensure Burp intercepts these and that your browser can reach the proxy.


## Security/Privacy notes

- `hook.js` only reports small JSON blobs to `/__capture__` for correlation and plaintext display. These are dropped locally by the extension and never forwarded to the backend.
- Use this tool only on systems you are authorized to test.


## Known limitations

- The hook targets a function named `AesRsaEncrypt`. If the application uses a different function name or different framework patterns, you may need to adapt the hook logic.
- The IV correlation assumes the same IV appears in the encrypted request JSON body and in the capture beacon; if the app changes IV semantics, correlation may fail.
- Only AES‑CBC/PKCS7 is supported.


## Roadmap / Future improvements

- Make the hook more adaptive: discover and wrap multiple possible encrypt functions.
- Pretty‑print/beautify JSON in the editors and add quick formatting toggles.
- Per‑site configuration profiles and persistence (save/load settings between sessions).
- TTL management and cleanup UI for IV correlation mappings.
- Optional display of capture diagnostics (without cluttering the main table).
- Support for additional cipher modes and authenticated encryption schemes (e.g., AES‑GCM) when applicable.
- Smarter response detection (handle nested envelopes or different field names).
- Unit tests and integration test harness for crypto and parsing utilities.


## License

For internal/research use. Review and comply with the license terms of Burp Suite and the Montoya API.
