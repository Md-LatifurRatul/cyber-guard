/**
 * CyberGuard Security Service Worker
 *
 * ## What is a Service Worker:
 * A script that runs in the background, separate from the web page.
 * It acts as a proxy between the browser and the network. It can
 * intercept, modify, and cache network requests and responses.
 *
 * ## Why we need one:
 * Regular JavaScript cannot modify HTTP response headers. But security
 * headers (CSP, X-Frame-Options) must be on the HTTP response.
 * A Service Worker can add these headers to every response.
 *
 * ## Lifecycle:
 * 1. Browser downloads and registers the SW (from security_guard.js)
 * 2. 'install' event — SW is installed, calls skipWaiting() to activate immediately
 * 3. 'activate' event — SW takes control, calls clients.claim()
 * 4. 'fetch' event — SW intercepts EVERY network request from the page
 *
 * ## Security headers we add:
 *
 * ### Content-Security-Policy (CSP)
 * Controls what resources the page can load:
 * - `default-src 'self'`: Only load resources from same origin
 * - `script-src 'self' 'unsafe-inline' 'unsafe-eval'`: Scripts from same origin
 *   (unsafe-inline/eval needed for Flutter CanvasKit)
 * - `frame-ancestors 'none'`: Prevents embedding in iframes (clickjacking)
 * - `object-src 'none'`: Blocks Flash/Java applets
 *
 * ### X-Frame-Options: DENY
 * Legacy header (superseded by frame-ancestors) that prevents the page
 * from being loaded in an iframe. Some older browsers don't support CSP
 * frame-ancestors, so we include both.
 *
 * ### X-Content-Type-Options: nosniff
 * Prevents browsers from MIME-sniffing a response away from the declared
 * content-type. Stops attacks where a malicious file is disguised as
 * a different content type.
 *
 * ### Referrer-Policy: strict-origin-when-cross-origin
 * Controls how much referrer information is sent with requests.
 * Prevents leaking the full URL (which might contain tokens/IDs)
 * to third-party origins.
 *
 * ### Permissions-Policy
 * Controls which browser features are available to the page.
 * We deny: camera, microphone, geolocation (not needed by our app).
 * This prevents malicious scripts from accessing these APIs.
 */

// ─── INSTALL ───

self.addEventListener("install", function (event) {
  // skipWaiting() forces the new SW to activate immediately,
  // rather than waiting for all tabs to close.
  // This ensures security updates take effect right away.
  self.skipWaiting();
});

// ─── ACTIVATE ───

self.addEventListener("activate", function (event) {
  // clients.claim() makes this SW control all open tabs immediately.
  // Without it, the SW only controls tabs opened AFTER activation.
  event.waitUntil(self.clients.claim());
});

// ─── FETCH INTERCEPT ───

self.addEventListener("fetch", function (event) {
  const url = new URL(event.request.url);

  // Only intercept same-origin requests.
  // Cross-origin requests (CDN, API) should pass through unchanged.
  if (url.origin !== self.location.origin) {
    return;
  }

  event.respondWith(
    fetch(event.request).then(function (response) {
      // Clone the response because Response body can only be read once.
      // We need to read it to create a new response with added headers.
      const newHeaders = new Headers(response.headers);

      // ─── Add security headers ───

      // CSP: Control resource loading
      // 'unsafe-inline' and 'unsafe-eval' are needed for Flutter CanvasKit.
      // In production, you'd want to use nonces instead, but Flutter
      // generates inline scripts dynamically, making nonces impractical.
      if (!newHeaders.has("Content-Security-Policy")) {
        newHeaders.set(
          "Content-Security-Policy",
          [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: blob:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "base-uri 'self'",
          ].join("; ")
        );
      }

      // Prevent iframe embedding (clickjacking protection)
      if (!newHeaders.has("X-Frame-Options")) {
        newHeaders.set("X-Frame-Options", "DENY");
      }

      // Prevent MIME type sniffing
      if (!newHeaders.has("X-Content-Type-Options")) {
        newHeaders.set("X-Content-Type-Options", "nosniff");
      }

      // Control referrer information leakage
      if (!newHeaders.has("Referrer-Policy")) {
        newHeaders.set("Referrer-Policy", "strict-origin-when-cross-origin");
      }

      // Restrict browser feature access
      if (!newHeaders.has("Permissions-Policy")) {
        newHeaders.set(
          "Permissions-Policy",
          "camera=(), microphone=(), geolocation=(), display-capture=()"
        );
      }

      // Create new response with security headers
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
    }).catch(function (err) {
      // Network error — return a basic error response
      // rather than letting the request hang
      return new Response("Network error", {
        status: 503,
        statusText: "Service Unavailable",
      });
    })
  );
});
