# AES‑CBC Auto Decrypter (Burp Suite Montoya extension)

A Burp Suite extension that understands a common “encrypted JSON envelope” used by some single‑page apps:

{
  "content": "<base64 AES/CBC ciphertext>",
  "iv": "<IV>",
  "key": "<optional RSA‑wrapped AES key>"
}

It automatically:
- Decrypts matching JSON responses in Proxy/Repeater so you can read plaintext without leaving Burp.
- (Optionally) Encrypts your plaintext Repeater requests back into the same envelope, ready to send to the target.
- Captures the site’s RSA public key from a known endpoint and uses it to wrap the AES key when needed.
- Injects a tiny JS “hook” into the frontend bundle to beacon plaintext and IV back to Burp for perfect request/response correlation.

This makes working with AES‑wrapped APIs feel native in Burp.


## How it works (high level)

- Traffic selection by origin
  - You choose an Origin (scheme://host[:port]) in the UI. Only traffic to that origin is processed, reducing noise and risk.

- Decrypt on the way back
  - If a response has Content‑Type: application/json and JSON fields content and iv, the extension uses your AES key + the response IV to decrypt content and replaces the body with the plaintext. The table logs both the original and the displayed version.
  - IV parsing supports Base64, base64url, and hex. The AES key can be Base64, hex, or it will (as a last resort for decryption only) fall back to UTF‑8 bytes.

- Encrypt on the way out (Repeater)
  - If you enable “Encrypt Repeater,” the extension takes your plaintext body and builds:
    {"content":"<b64>","key":"<maybe>","iv":"<b64>"}
  - Key parameter: If “always set” is chosen or the path ends with /UserLogin, the extension RSA‑wraps the AES key using the captured/provided RSA public key and puts it in key.
  - IV handling: If you provided an IV (as Base64 of 32 bytes), it uses that and AES uses the first 16 bytes. Otherwise, the extension generates a fresh 32‑byte IV for the envelope and uses its first 16 bytes for AES.

- RSA public key auto‑capture
  - If a GET to /getRSAPublicKey (or paths that end with it) returns JSON containing RSAPublicKey, the extension will extract and store the PEM.

- Frontend “hook” for perfect plaintext correlation
  - The extension injects a small JS snippet into /static/js/app.js responses. The hook observes XMLHttpRequest/fetch calls, extracts plaintext (before encryption) and IV, and sends a short beacon back to Burp at a private path /__capture__ (never forwarded upstream). This lets the UI show the exact plaintext for the matching request row even if Burp encrypted it on the fly.
  - You can fully edit this hook in the “Hook” tab and persist your version. A default is bundled.


## What you’ll see in Burp

- Suite tab “AES Decrypt”
  - Controls: Enable/disable feature, Origin, AES key, IV, RSA public key, and a “Key parameter mode” (e.g., always set). A table lists each processed exchange with columns Time, Method, URL, Status, Decrypted, Note.
  - Selecting a row shows the request/response with the best available plaintext view (captured, locally decrypted, or original).

- Suite tab “Hook”
  - A text area with the current JS hook source. Edits persist. “Reset to default” restores the bundled hook.

- Context menu
  - Right‑click any request and choose “AES Decryptor: Set origin to …” to quickly target the site you’re testing.


## Quick start

1) Build the extension
- Requires Java 17+ and Gradle. From the repository root:
  ./gradlew :ExtensionTemplateProject:build
- The JAR will be in ExtensionTemplateProject/build/libs

2) Load into Burp
- Burp Suite -> Extensions -> Add -> Select the built JAR.
- The extension name will appear as “AES‑CBC Auto Decrypter.” Two suite tabs will be added: AES Decrypt and Hook.

3) Configure
- In the AES Decrypt tab:
  - Origin: Click the context menu on a request from the target to set it automatically, or paste it (e.g., https://target.example.com).
  - AES key: Paste Base64 (preferred) or hex.
  - RSA public key: Optional PEM. If the app serves it at /getRSAPublicKey, the extension will capture it automatically when you browse the login page.
  - IV: Optional. If empty, Repeater encryption will generate one per request.
  - Encrypt Repeater: Enable if you want plaintext you type in Repeater to be wrapped as the encrypted JSON envelope.
  - Key parameter mode: Choose when to include the RSA‑wrapped AES key (e.g., “always set”).

- In the Hook tab:
  - Keep the default hook or customize it. The hook is injected into /static/js/app.js responses automatically. If the app’s main bundle lives at a different path, you can still copy the hook and inject it manually (e.g., via a user script or devtools) or alter the extension code to change the injection path.

4) Use it
- In Proxy: Browse the app. Matching JSON responses will show decrypted plaintext automatically. Notes will tell you what happened (e.g., decrypted, missing key/iv).
- In Repeater: Type plaintext into the body, enable “Encrypt Repeater,” and send. The extension will wrap it. If the hook captured plaintext for that IV, the table will show the exact plaintext next to the encrypted request.


## Data formats and expectations

- Envelope fields in requests/responses:
  - content: Base64 of AES/CBC/PKCS5 ciphertext of the plaintext JSON body.
  - iv: Base64 (32‑byte preferred), base64url, or hex are accepted for decryption. For Repeater encryption, the UI IV (if provided) must be Base64 that decodes to 32 bytes; AES uses the first 16 bytes.
  - key: Base64 RSA/PKCS#1 v1.5 ciphertext of the ASCII bytes of the AES key text (which, in typical deployments, is Base64). Included when required by the endpoint.

- Content‑Type: application/json is required for response decryption.

- Auto‑capture endpoints:
  - RSA public key: GET /getRSAPublicKey (JSON field RSAPublicKey)
  - Hook injection target: any response with a path ending in /static/js/app.js
  - Hook beacon path inside Burp: /__capture__ (handled and dropped by the extension; never forwarded)


## Security and safety notes

- This extension modifies traffic in your Burp session. Keep the Origin restricted to only the target you intend to test.
- AES key and captured plaintext live only in your running Burp process. Don’t share your Burp project if it contains sensitive values.
- RSA and AES operations are as implemented in javax.crypto with AES/CBC/PKCS5Padding and RSA/ECB/PKCS1Padding.
- For decryption helpers, the extension tries to “do what I mean” by accepting Base64, base64url, or hex. For encryption (Repeater), it is strict and will reject invalid inputs rather than guess.


## Troubleshooting

- I see “Skipping non‑JSON response”
  - Ensure the server sets Content‑Type: application/json on encrypted responses.

- “Missing key/iv” or “Response missing content/iv fields”
  - The body didn’t match the expected envelope. Check if the app uses a different field name or a different endpoint shape.

- RSA public key wasn’t captured
  - Browse the endpoint /getRSAPublicKey while the extension is enabled, or paste the PEM in the UI.

- Repeater didn’t encrypt my body
  - Ensure “Encrypt Repeater” is on, method is POST/PUT/PATCH, and you have provided a valid Base64 AES key. If IV is empty, the extension will generate one. If key/IV inputs are invalid, the extension will fall back to sending your plaintext as-is.

- The app’s JS isn’t at /static/js/app.js
  - The automatic injection looks for that exact path suffix. Use the Hook tab’s code manually (copy/paste into a user script, Chrome devtools Snippets, or a local bundle override). Changing the injection path requires a small code tweak in DecryptingHttpHandler.


## Building and testing

- Build: ./gradlew :ExtensionTemplateProject:build
- Unit tests: ./gradlew :ExtensionTemplateProject:test
  - Includes CryptoFlowTest with known‑good vectors verifying AES and RSA behavior.


## Files of interest

- ExtensionTemplateProject/src/main/java/Extension.java — Montoya entrypoint; registers tabs, handlers, and context menu.
- DecryptingHttpHandler.java — Core HTTP logic: request mapping, response decryption, Repeater encryption, hook injection, RSA key capture.
- CaptureProxyHandler.java — Handles the /__capture__ beacons and maps captured plaintext to requests by IV.
- HookTabPanel.java & HookSettings.java — UI and persistence for the editable JS hook.
- HookPayload.java — Bundled default JS hook source.
- DecryptTabPanel.java — Main UI: inputs, table, controls.
- AESCbcDecryptor.java / AESCbcEncryptor.java — Crypto helpers (decryption is lenient; encryption uses strict inputs).
- RsaUtil.java — RSA wrapping of the AES key.
- IvRequestMap.java / RequestDisplayStore.java — Correlation stores for IV→messageId and prepared plaintext views.
- hook.js — Standalone copy of the hook for manual injection/use.

