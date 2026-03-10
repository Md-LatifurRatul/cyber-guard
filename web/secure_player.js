/**
 * CyberGuard Secure Player — Web Bridge
 *
 * Manages HTML5 <video> elements for Flutter's HtmlElementView on web.
 * Each player instance gets a unique element ID registered with Flutter's
 * platform view system.
 *
 * Security layers applied:
 * - CSS user-select: none (prevent text selection on controls)
 * - Context menu disabled on video element
 * - Canvas readback already blocked by security_guard.js
 * - No download attribute, controlsList nodownload
 *
 * Called from Dart via js_interop / MethodChannel web implementation.
 */
(function () {
  'use strict';

  /** @type {Map<string, HTMLVideoElement>} */
  const players = new Map();

  /** @type {Map<string, function>} */
  const eventCallbacks = new Map();

  let playerCounter = 0;

  /**
   * Create a new player instance.
   * @param {object} params - { source, config }
   * @returns {{ playerId: string, elementId: string }}
   */
  function createPlayer(params) {
    const playerId = `cyberguard_player_${++playerCounter}`;
    const video = document.createElement('video');

    // Core attributes
    video.id = playerId;
    video.style.width = '100%';
    video.style.height = '100%';
    video.style.objectFit = _mapFit(params.config?.fit || 'contain');
    video.style.backgroundColor = '#000';
    video.playsInline = true;
    video.setAttribute('playsinline', '');
    video.setAttribute('webkit-playsinline', '');

    // Security: disable native controls download
    video.setAttribute('controlsList', 'nodownload noremoteplayback');
    video.setAttribute('disablePictureInPicture', '');
    video.removeAttribute('controls');

    // Prevent context menu
    video.addEventListener('contextmenu', function (e) {
      e.preventDefault();
      return false;
    });

    // Prevent drag
    video.addEventListener('dragstart', function (e) {
      e.preventDefault();
    });

    // CSS security
    video.style.userSelect = 'none';
    video.style.webkitUserSelect = 'none';
    video.style.pointerEvents = 'none'; // Flutter handles all gestures

    // Set source
    const source = params.source || {};
    if (source.type === 'network' || source.type === 'liveStream') {
      video.src = source.url;
    } else if (source.type === 'asset') {
      video.src = 'assets/' + source.assetPath;
    } else if (source.type === 'file') {
      video.src = source.filePath;
    } else if (source.type === 'memory' && source.bytes) {
      const blob = new Blob([source.bytes], { type: source.mimeType || 'video/mp4' });
      video.src = URL.createObjectURL(blob);
    }

    // Apply config
    if (params.config) {
      video.volume = params.config.volume ?? 1.0;
      video.playbackRate = params.config.speed ?? 1.0;
      video.loop = params.config.looping ?? false;
    }

    // Register event listeners
    _attachEvents(playerId, video);

    // Add to DOM (hidden container for Flutter's HtmlElementView)
    let container = document.getElementById('cyberguard-player-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'cyberguard-player-container';
      container.style.position = 'fixed';
      container.style.top = '-9999px';
      container.style.left = '-9999px';
      container.style.width = '1px';
      container.style.height = '1px';
      container.style.overflow = 'hidden';
      document.body.appendChild(container);
    }
    container.appendChild(video);

    players.set(playerId, video);

    return { playerId: playerId, elementId: playerId };
  }

  /**
   * Play the video.
   * @param {string} playerId
   */
  function play(playerId) {
    const video = players.get(playerId);
    if (!video) return;
    video.play().catch(function (e) {
      _sendEvent(playerId, 'onError', { message: e.message });
    });
  }

  /**
   * Pause the video.
   * @param {string} playerId
   */
  function pause(playerId) {
    const video = players.get(playerId);
    if (video) video.pause();
  }

  /**
   * Seek to position in milliseconds.
   * @param {string} playerId
   * @param {number} positionMs
   */
  function seekTo(playerId, positionMs) {
    const video = players.get(playerId);
    if (video) video.currentTime = positionMs / 1000;
  }

  /**
   * Set volume (0.0 - 1.0).
   * @param {string} playerId
   * @param {number} volume
   */
  function setVolume(playerId, volume) {
    const video = players.get(playerId);
    if (video) video.volume = Math.max(0, Math.min(1, volume));
  }

  /**
   * Set playback speed.
   * @param {string} playerId
   * @param {number} speed
   */
  function setPlaybackSpeed(playerId, speed) {
    const video = players.get(playerId);
    if (video) video.playbackRate = Math.max(0.25, Math.min(4, speed));
  }

  /**
   * Get current position and buffer status.
   * @param {string} playerId
   * @returns {{ positionMs: number, bufferedMs: number }}
   */
  function getPosition(playerId) {
    const video = players.get(playerId);
    if (!video) return { positionMs: 0, bufferedMs: 0 };

    let bufferedMs = 0;
    if (video.buffered.length > 0) {
      bufferedMs = video.buffered.end(video.buffered.length - 1) * 1000;
    }

    return {
      positionMs: Math.round(video.currentTime * 1000),
      bufferedMs: Math.round(bufferedMs),
    };
  }

  /**
   * Dispose a player instance.
   * @param {string} playerId
   */
  function disposePlayer(playerId) {
    const video = players.get(playerId);
    if (!video) return;

    video.pause();
    video.removeAttribute('src');
    video.load();

    // Revoke blob URL if used
    if (video.src && video.src.startsWith('blob:')) {
      URL.revokeObjectURL(video.src);
    }

    // Remove from DOM
    if (video.parentNode) {
      video.parentNode.removeChild(video);
    }

    players.delete(playerId);
    eventCallbacks.delete(playerId);
  }

  // ─── Internal ───

  function _attachEvents(playerId, video) {
    video.addEventListener('loadedmetadata', function () {
      _sendEvent(playerId, 'onReady', {
        durationMs: Math.round(video.duration * 1000) || 0,
        videoWidth: video.videoWidth || 0,
        videoHeight: video.videoHeight || 0,
      });
    });

    video.addEventListener('playing', function () {
      _sendEvent(playerId, 'onPlaying', {});
    });

    video.addEventListener('pause', function () {
      _sendEvent(playerId, 'onPaused', {});
    });

    video.addEventListener('waiting', function () {
      _sendEvent(playerId, 'onBuffering', {});
    });

    video.addEventListener('ended', function () {
      _sendEvent(playerId, 'onCompleted', {});
    });

    video.addEventListener('error', function () {
      const error = video.error;
      _sendEvent(playerId, 'onError', {
        message: error ? error.message || 'Media error code: ' + error.code : 'Unknown error',
      });
    });

    video.addEventListener('resize', function () {
      _sendEvent(playerId, 'onVideoSizeChanged', {
        width: video.videoWidth || 0,
        height: video.videoHeight || 0,
      });
    });
  }

  function _sendEvent(playerId, eventName, data) {
    // Events are dispatched as CustomEvents for Dart's js_interop to capture
    const event = new CustomEvent('cyberguard_player_event', {
      detail: {
        playerId: playerId,
        event: eventName,
        data: data,
      },
    });
    window.dispatchEvent(event);
  }

  function _mapFit(fit) {
    switch (fit) {
      case 'cover': return 'cover';
      case 'fill': return 'fill';
      default: return 'contain';
    }
  }

  // ─── Public API ───

  window.CyberGuardPlayer = {
    create: createPlayer,
    play: play,
    pause: pause,
    seekTo: seekTo,
    setVolume: setVolume,
    setPlaybackSpeed: setPlaybackSpeed,
    getPosition: getPosition,
    dispose: disposePlayer,
  };
})();
