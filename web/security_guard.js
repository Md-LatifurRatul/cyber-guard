/**
 * CyberGuard Web Security Engine
 *
 * ## Architecture:
 * This is the browser-side security layer. It runs as plain JavaScript
 * alongside the Flutter web app. Dart communicates with it via
 * dart:js_interop through the global `CyberGuardSecurity` object.
 *
 * ## Why JavaScript (not Dart):
 * Browser security APIs (Canvas prototype, navigator.mediaDevices,
 * keyboard events, window dimensions) must be overridden at the
 * JavaScript level BEFORE Flutter/Dart loads. Dart's dart:html is
 * deprecated; dart:js_interop can call JS but can't override prototypes
 * early enough. So: JS does the heavy lifting, Dart orchestrates.
 *
 * ## Protection layers:
 * 1. Canvas/WebGL readback prevention (toDataURL, getImageData, readPixels)
 * 2. Screen sharing block (getDisplayMedia override)
 * 3. DevTools detection (3 independent methods)
 * 4. Keyboard shortcut interception (PrtScn, Ctrl+S, F12, etc.)
 * 5. Right-click / text selection / drag prevention
 * 6. CSS injection for content protection
 *
 * ## Lifecycle:
 *   CyberGuardSecurity.initialize(config)  → set up protections
 *   CyberGuardSecurity.activate()          → enable all protections
 *   CyberGuardSecurity.deactivate()        → disable protections
 *   CyberGuardSecurity.getStatus()         → return current status
 *
 * ## Event callback:
 *   CyberGuardSecurity.onSecurityEvent = function(event) { ... }
 *   Called whenever a security-relevant action is detected.
 *   Dart registers this callback to feed events into SecurityChannel.
 */
(function () {
  "use strict";

  // ═══════════════════════════════════════════════════════════════
  // STATE
  // ═══════════════════════════════════════════════════════════════

  let _active = false;
  let _initialized = false;
  let _devToolsOpen = false;
  let _devToolsCheckInterval = null;

  // Store original functions before overriding
  const _originals = {
    toDataURL: null,
    toBlob: null,
    getImageData: null,
    readPixelsWebGL: null,
    readPixelsWebGL2: null,
    getDisplayMedia: null,
  };

  // ═══════════════════════════════════════════════════════════════
  // LAYER 1: CANVAS / WEBGL READBACK PREVENTION
  // ═══════════════════════════════════════════════════════════════

  /**
   * Override HTMLCanvasElement.prototype.toDataURL
   *
   * ## How screenshots work on web:
   * Browser extensions and JS-based capture tools call toDataURL()
   * on canvas elements to extract pixel data as a base64 string.
   * Flutter renders to a <canvas> element in CanvasKit mode.
   * By overriding toDataURL, we return a blank image instead of
   * the actual content.
   *
   * ## Why this works:
   * JavaScript prototype chain: when any code calls canvas.toDataURL(),
   * it walks up the prototype chain to HTMLCanvasElement.prototype.
   * By replacing the function there, ALL canvas elements are affected.
   *
   * ## Limitation:
   * This does NOT prevent OS-level screenshots (PrtScn key, Snipping Tool).
   * Those capture the composited framebuffer, which we can't intercept
   * from JavaScript.
   */
  function installCanvasProtection() {
    // --- toDataURL ---
    _originals.toDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (type, quality) {
      if (!_active) return _originals.toDataURL.call(this, type, quality);

      _emitEvent("screenCapture", "high", { method: "toDataURL" });

      // Return a 1x1 transparent PNG instead of actual content
      return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    };

    // --- toBlob ---
    _originals.toBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function (callback, type, quality) {
      if (!_active)
        return _originals.toBlob.call(this, callback, type, quality);

      _emitEvent("screenCapture", "high", { method: "toBlob" });

      // Return a blank blob
      const blankCanvas = document.createElement("canvas");
      blankCanvas.width = 1;
      blankCanvas.height = 1;
      _originals.toBlob.call(blankCanvas, callback, type, quality);
    };

    // --- getImageData (2D context) ---
    if (CanvasRenderingContext2D) {
      _originals.getImageData =
        CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = function (
        sx,
        sy,
        sw,
        sh,
        settings
      ) {
        if (!_active)
          return _originals.getImageData.call(this, sx, sy, sw, sh, settings);

        _emitEvent("screenCapture", "high", { method: "getImageData" });

        // Return blank ImageData (all zeros = transparent black)
        return new ImageData(Math.abs(sw), Math.abs(sh));
      };
    }

    // --- readPixels (WebGL) ---
    if (typeof WebGLRenderingContext !== "undefined") {
      _originals.readPixelsWebGL =
        WebGLRenderingContext.prototype.readPixels;
      WebGLRenderingContext.prototype.readPixels = function (
        x, y, w, h, format, type, pixels
      ) {
        if (!_active)
          return _originals.readPixelsWebGL.call(
            this, x, y, w, h, format, type, pixels
          );

        _emitEvent("screenCapture", "high", { method: "readPixels_webgl" });
        // pixels array stays all zeros (default)
      };
    }

    // --- readPixels (WebGL2) ---
    if (typeof WebGL2RenderingContext !== "undefined") {
      _originals.readPixelsWebGL2 =
        WebGL2RenderingContext.prototype.readPixels;
      WebGL2RenderingContext.prototype.readPixels = function (
        x, y, w, h, format, type, pixels, dstOffset
      ) {
        if (!_active)
          return _originals.readPixelsWebGL2.call(
            this, x, y, w, h, format, type, pixels, dstOffset
          );

        _emitEvent("screenCapture", "high", { method: "readPixels_webgl2" });
        // pixels array stays all zeros (default)
      };
    }
  }

  /**
   * Restore original canvas functions when deactivating.
   */
  function uninstallCanvasProtection() {
    if (_originals.toDataURL) {
      HTMLCanvasElement.prototype.toDataURL = _originals.toDataURL;
    }
    if (_originals.toBlob) {
      HTMLCanvasElement.prototype.toBlob = _originals.toBlob;
    }
    if (_originals.getImageData) {
      CanvasRenderingContext2D.prototype.getImageData =
        _originals.getImageData;
    }
    if (_originals.readPixelsWebGL && typeof WebGLRenderingContext !== "undefined") {
      WebGLRenderingContext.prototype.readPixels =
        _originals.readPixelsWebGL;
    }
    if (_originals.readPixelsWebGL2 && typeof WebGL2RenderingContext !== "undefined") {
      WebGL2RenderingContext.prototype.readPixels =
        _originals.readPixelsWebGL2;
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // LAYER 2: SCREEN SHARING BLOCK
  // ═══════════════════════════════════════════════════════════════

  /**
   * Override navigator.mediaDevices.getDisplayMedia
   *
   * ## What getDisplayMedia does:
   * It's the browser API that lets JavaScript capture the screen,
   * a window, or a tab. Used by screen sharing in Zoom, Meet, etc.
   * Also used by extensions to record the screen.
   *
   * ## Our override:
   * We reject the promise with NotAllowedError, making it look like
   * the user denied the permission prompt. This is indistinguishable
   * from a real denial, so the calling code handles it gracefully.
   */
  function installScreenShareBlock() {
    if (
      navigator.mediaDevices &&
      navigator.mediaDevices.getDisplayMedia
    ) {
      _originals.getDisplayMedia =
        navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);

      navigator.mediaDevices.getDisplayMedia = function (constraints) {
        if (!_active)
          return _originals.getDisplayMedia(constraints);

        _emitEvent("screenCapture", "high", {
          method: "getDisplayMedia_blocked",
        });

        return Promise.reject(
          new DOMException(
            "Screen capture is not allowed.",
            "NotAllowedError"
          )
        );
      };
    }
  }

  function uninstallScreenShareBlock() {
    if (_originals.getDisplayMedia && navigator.mediaDevices) {
      navigator.mediaDevices.getDisplayMedia = _originals.getDisplayMedia;
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // LAYER 3: DEVTOOLS DETECTION
  // ═══════════════════════════════════════════════════════════════

  /**
   * DevTools detection using 3 independent methods.
   *
   * ## Method 1: Window size differential
   * When DevTools is docked (bottom/right/left), the browser's
   * inner dimensions shrink while outer dimensions stay the same.
   * A difference > 160px strongly indicates DevTools.
   * Note: This doesn't detect undocked (separate window) DevTools.
   *
   * ## Method 2: console.log with getter trap
   * When DevTools console is open, Chrome evaluates objects passed
   * to console.log(). We create an object with a custom getter on
   * its `id` property. The getter fires ONLY when DevTools reads
   * the object — giving us a reliable detection signal.
   *
   * ## Method 3: debugger statement timing
   * The `debugger` statement pauses execution when DevTools is open.
   * If DevTools is closed, it takes ~0ms. If open, it takes >100ms
   * because the debugger UI pauses. We measure the time delta.
   * NOTE: We use this sparingly (every 5s) because it can cause
   * brief UI jank if DevTools IS open.
   *
   * ## Why 3 methods:
   * Each method has blind spots. Window size misses undocked DevTools.
   * Console trap only works when the Console tab is active.
   * Debugger timing causes minor jank. Together, they cover all cases.
   */
  function startDevToolsDetection() {
    if (_devToolsCheckInterval) return;

    let checkCount = 0;

    _devToolsCheckInterval = setInterval(function () {
      let detected = false;

      // Method 1: Window size differential
      const widthDiff = window.outerWidth - window.innerWidth;
      const heightDiff = window.outerHeight - window.innerHeight;
      if (widthDiff > 160 || heightDiff > 160) {
        detected = true;
      }

      // Method 2: Console trap (every check)
      const trapObj = new Image();
      Object.defineProperty(trapObj, "id", {
        get: function () {
          detected = true;
        },
      });
      // Force DevTools to read the object if Console is open
      console.log("%c", "font-size:0;", trapObj);
      // Clear the console to hide our detection artifacts
      console.clear();

      // Method 3: Debugger timing (every 5th check to reduce jank)
      // Disabled by default — uncomment if stronger detection needed
      // checkCount++;
      // if (checkCount % 5 === 0) {
      //   const start = performance.now();
      //   debugger;
      //   if (performance.now() - start > 100) {
      //     detected = true;
      //   }
      // }

      // State change detection
      if (detected && !_devToolsOpen) {
        _devToolsOpen = true;
        _emitEvent("devToolsOpened", "medium", {
          method: widthDiff > 160 || heightDiff > 160
            ? "window_size"
            : "console_trap",
        });
      } else if (!detected && _devToolsOpen) {
        _devToolsOpen = false;
        // DevTools closed — could emit a "cleared" event here
      }
    }, 1000); // Check every 1 second
  }

  function stopDevToolsDetection() {
    if (_devToolsCheckInterval) {
      clearInterval(_devToolsCheckInterval);
      _devToolsCheckInterval = null;
    }
    _devToolsOpen = false;
  }

  // ═══════════════════════════════════════════════════════════════
  // LAYER 4: KEYBOARD SHORTCUT INTERCEPTION
  // ═══════════════════════════════════════════════════════════════

  /**
   * Block keyboard shortcuts used for:
   * - Screenshots (PrintScreen)
   * - Saving page (Ctrl+S)
   * - Printing (Ctrl+P)
   * - Opening DevTools (F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C)
   * - Viewing source (Ctrl+U)
   *
   * ## How this works:
   * We listen on `keydown` with `capture: true` (fires BEFORE any
   * other handlers). If the key combo matches a blocked shortcut,
   * we call `preventDefault()` and `stopPropagation()` to consume
   * the event completely.
   *
   * ## Limitations:
   * - Can't block OS-level shortcuts (Win+PrtScn, macOS Cmd+Shift+3)
   * - Some browsers don't allow blocking F12 in all contexts
   * - Can be bypassed by disabling JavaScript (but then the app won't work)
   */
  function _handleKeyDown(e) {
    if (!_active) return;

    const dominated =
      // PrintScreen
      e.key === "PrintScreen" ||
      // F12 (DevTools)
      e.key === "F12" ||
      // Ctrl/Cmd + S (Save)
      ((e.ctrlKey || e.metaKey) && e.key === "s") ||
      // Ctrl/Cmd + P (Print)
      ((e.ctrlKey || e.metaKey) && e.key === "p") ||
      // Ctrl/Cmd + U (View Source)
      ((e.ctrlKey || e.metaKey) && e.key === "u") ||
      // Ctrl/Cmd + Shift + I (DevTools)
      ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "I") ||
      // Ctrl/Cmd + Shift + J (Console)
      ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "J") ||
      // Ctrl/Cmd + Shift + C (Inspect Element)
      ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "C") ||
      // Ctrl/Cmd + Shift + S (Save As)
      ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "S");

    if (dominated) {
      e.preventDefault();
      e.stopPropagation();
      _emitEvent("screenCapture", "low", {
        method: "keyboard_blocked",
        key: e.key,
      });
    }
  }

  function installKeyboardProtection() {
    document.addEventListener("keydown", _handleKeyDown, {
      capture: true,
      passive: false,
    });
  }

  function uninstallKeyboardProtection() {
    document.removeEventListener("keydown", _handleKeyDown, {
      capture: true,
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // LAYER 5: RIGHT-CLICK / SELECTION / DRAG PREVENTION
  // ═══════════════════════════════════════════════════════════════

  /**
   * Block the browser context menu (right-click).
   *
   * The context menu provides "Save Image As", "Copy Image",
   * "Inspect Element", and other options that leak content.
   * We block it on the entire document when secure mode is active.
   */
  function _handleContextMenu(e) {
    if (!_active) return;
    e.preventDefault();
    _emitEvent("screenCapture", "low", { method: "context_menu_blocked" });
  }

  /**
   * Block text selection via selectstart event.
   *
   * Prevents users from selecting and copying text content
   * displayed in the secure viewer.
   */
  function _handleSelectStart(e) {
    if (!_active) return;
    e.preventDefault();
  }

  /**
   * Block drag operations on content.
   *
   * Users can drag images and text to the desktop or other apps.
   * This prevents that interaction.
   */
  function _handleDragStart(e) {
    if (!_active) return;
    e.preventDefault();
  }

  function installInteractionProtection() {
    document.addEventListener("contextmenu", _handleContextMenu, {
      capture: true,
    });
    document.addEventListener("selectstart", _handleSelectStart, {
      capture: true,
    });
    document.addEventListener("dragstart", _handleDragStart, {
      capture: true,
    });
  }

  function uninstallInteractionProtection() {
    document.removeEventListener("contextmenu", _handleContextMenu, {
      capture: true,
    });
    document.removeEventListener("selectstart", _handleSelectStart, {
      capture: true,
    });
    document.removeEventListener("dragstart", _handleDragStart, {
      capture: true,
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // LAYER 6: CSS INJECTION
  // ═══════════════════════════════════════════════════════════════

  /**
   * Inject CSS rules that prevent content extraction.
   *
   * ## What each rule does:
   * - `user-select: none`: Prevents text selection
   * - `-webkit-user-drag: none`: Prevents dragging on WebKit browsers
   * - `pointer-events: auto`: Ensures our overlay captures all events
   * - `print-color-adjust: exact`: Ensures watermarks print accurately
   *
   * ## @media print:
   * When the user tries to print (even after we block Ctrl+P,
   * they can use the browser menu), we hide all body content
   * and show a warning message instead.
   */
  const SECURITY_STYLE_ID = "cyberguard-security-styles";

  function injectSecurityCSS() {
    if (document.getElementById(SECURITY_STYLE_ID)) return;

    const style = document.createElement("style");
    style.id = SECURITY_STYLE_ID;
    style.textContent = `
      /* Prevent text selection on the entire page when secure mode is active */
      body.cyberguard-secure {
        -webkit-user-select: none !important;
        -moz-user-select: none !important;
        -ms-user-select: none !important;
        user-select: none !important;
        -webkit-user-drag: none !important;
        -webkit-touch-callout: none !important;
      }

      /* When printing, hide all content and show a warning */
      @media print {
        body.cyberguard-secure * {
          visibility: hidden !important;
        }
        body.cyberguard-secure::after {
          visibility: visible !important;
          position: fixed;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          content: "Protected content — printing is not permitted.";
          font-size: 24px;
          color: #333;
          font-family: -apple-system, BlinkMacSystemFont, sans-serif;
          text-align: center;
        }
      }
    `;
    document.head.appendChild(style);
  }

  function removeSecurityCSS() {
    const style = document.getElementById(SECURITY_STYLE_ID);
    if (style) style.remove();
  }

  // ═══════════════════════════════════════════════════════════════
  // EVENT SYSTEM
  // ═══════════════════════════════════════════════════════════════

  /**
   * Emit a security event to Dart.
   *
   * Dart registers a callback via CyberGuardSecurity.onSecurityEvent.
   * Events follow the same schema as native SecurityEvent:
   *   { type: string, severity: string, timestamp: int, metadata: {} }
   *
   * @param {string} type - SecurityEventType name (e.g. "screenCapture")
   * @param {string} severity - "low" | "medium" | "high" | "critical"
   * @param {Object} metadata - Additional context
   */
  function _emitEvent(type, severity, metadata) {
    const event = {
      type: type,
      severity: severity,
      timestamp: Date.now(),
      metadata: metadata || {},
    };

    // Call Dart callback if registered
    if (typeof window.CyberGuardSecurity.onSecurityEvent === "function") {
      try {
        window.CyberGuardSecurity.onSecurityEvent(event);
      } catch (err) {
        // Dart callback error — don't let it break our security
        console.warn("CyberGuard: Event callback error:", err);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // SERVICE WORKER REGISTRATION
  // ═══════════════════════════════════════════════════════════════

  /**
   * Register the security Service Worker.
   *
   * ## What the Service Worker does:
   * - Intercepts all network requests
   * - Adds Content-Security-Policy headers to responses
   * - Blocks requests to known screen capture/recording endpoints
   *
   * ## Why a Service Worker:
   * Regular JavaScript can't modify HTTP response headers. But a
   * Service Worker acts as a network proxy — it can intercept
   * requests and modify responses, including adding security headers.
   */
  function registerServiceWorker() {
    if (!("serviceWorker" in navigator)) return;

    navigator.serviceWorker
      .register("security_sw.js", { scope: "/" })
      .then(function (reg) {
        console.log("CyberGuard: Service Worker registered (scope:", reg.scope + ")");
      })
      .catch(function (err) {
        // Service Worker registration can fail in development (http without cert)
        // or when the path is wrong. Non-fatal — other protections still work.
        console.warn("CyberGuard: Service Worker registration failed:", err);
      });
  }

  // ═══════════════════════════════════════════════════════════════
  // VISIBILITY API — Detect tab switching / window blur
  // ═══════════════════════════════════════════════════════════════

  /**
   * Monitor page visibility changes.
   *
   * When the user switches tabs or minimizes the window,
   * document.hidden becomes true. This is our "app backgrounded"
   * equivalent for web. We emit an event so Dart can apply blur
   * protection (same as iOS/Android app backgrounding).
   */
  function _handleVisibilityChange() {
    if (!_active) return;

    if (document.hidden) {
      _emitEvent("appBackgrounded", "low", { method: "visibility_hidden" });
    }
  }

  function installVisibilityMonitoring() {
    document.addEventListener("visibilitychange", _handleVisibilityChange);
  }

  function uninstallVisibilityMonitoring() {
    document.removeEventListener("visibilitychange", _handleVisibilityChange);
  }

  // ═══════════════════════════════════════════════════════════════
  // PUBLIC API — Global CyberGuardSecurity object
  // ═══════════════════════════════════════════════════════════════

  window.CyberGuardSecurity = {
    /**
     * Callback for security events. Set by Dart via js_interop.
     * @type {function|null}
     */
    onSecurityEvent: null,

    /**
     * Initialize the security engine. Call once at startup.
     *
     * Installs prototype overrides and event listeners, but doesn't
     * activate them yet. They check the `_active` flag before acting.
     *
     * @param {Object} config - Configuration from Dart
     * @param {boolean} config.enableCanvasProtection - Override canvas APIs
     * @param {boolean} config.enableDevToolsDetection - Monitor for DevTools
     * @param {boolean} config.enableKeyboardProtection - Block shortcuts
     * @param {boolean} config.enableScreenShareBlock - Block getDisplayMedia
     */
    initialize: function (config) {
      if (_initialized) return;

      config = config || {};

      // Install protections (dormant until activate())
      if (config.enableCanvasProtection !== false) {
        installCanvasProtection();
      }
      if (config.enableScreenShareBlock !== false) {
        installScreenShareBlock();
      }

      // Keyboard and interaction protection are always installed
      // (they check _active flag internally)
      installKeyboardProtection();
      installInteractionProtection();
      installVisibilityMonitoring();

      // Register Service Worker for CSP headers
      registerServiceWorker();

      _initialized = true;
      console.log("CyberGuard: Security engine initialized");
    },

    /**
     * Activate all protections. Call when entering secure content.
     *
     * This flips the `_active` flag, which causes all installed
     * overrides to start blocking. Also starts DevTools detection
     * polling and injects security CSS.
     */
    activate: function () {
      if (!_initialized) {
        console.warn("CyberGuard: Cannot activate — not initialized");
        return;
      }

      _active = true;

      // Start DevTools monitoring
      startDevToolsDetection();

      // Add CSS protections
      injectSecurityCSS();
      document.body.classList.add("cyberguard-secure");

      console.log("CyberGuard: Protections activated");
    },

    /**
     * Deactivate all protections. Call when leaving secure content.
     *
     * Flips `_active` to false, stops DevTools monitoring, and
     * removes security CSS. Canvas overrides remain installed but
     * pass through to originals when inactive.
     */
    deactivate: function () {
      _active = false;

      stopDevToolsDetection();
      removeSecurityCSS();
      document.body.classList.remove("cyberguard-secure");

      console.log("CyberGuard: Protections deactivated");
    },

    /**
     * Get current security status.
     * Called by Dart for getDeviceIntegrity().
     *
     * @returns {Object} Status map matching native integrity format
     */
    getStatus: function () {
      return {
        isDevToolsOpen: _devToolsOpen,
        isActive: _active,
        isInitialized: _initialized,
      };
    },

    /**
     * Destroy the security engine. Restores all original functions.
     * Call only on app shutdown — this is irreversible.
     */
    destroy: function () {
      _active = false;
      _initialized = false;

      stopDevToolsDetection();
      uninstallCanvasProtection();
      uninstallScreenShareBlock();
      uninstallKeyboardProtection();
      uninstallInteractionProtection();
      uninstallVisibilityMonitoring();
      removeSecurityCSS();
      document.body.classList.remove("cyberguard-secure");
    },
  };
})();
