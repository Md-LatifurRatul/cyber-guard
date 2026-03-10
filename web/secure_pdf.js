/**
 * CyberGuard Secure PDF Renderer — Web Platform.
 *
 * Provides a JavaScript bridge for the Dart PDF controller to render
 * PDF pages on web. Uses an embedded <iframe> with browser's native
 * PDF viewer as a fallback, and canvas-based rendering for pixel extraction.
 *
 * The Dart side communicates via window.CyberGuardPdf global API,
 * matching the MethodChannel contract on native platforms.
 *
 * @channel com.cyberguard.security/pdf
 */
(function () {
  'use strict';

  /** @type {Object<string, {url: string, pageCount: number}>} */
  const documents = {};

  let idCounter = 0;

  /**
   * Open a PDF document.
   * On web, we store the URL/blob URL for later rendering.
   * Page count detection requires fetching the PDF — we return 1 as default
   * and the Dart side can update when pages are actually rendered.
   *
   * @param {Object} source
   * @returns {Promise<{documentId: string, pageCount: number}>}
   */
  async function open(source) {
    const documentId = 'web_pdf_' + (++idCounter);
    let url = null;

    switch (source.type) {
      case 'network':
        url = source.url;
        break;
      case 'asset':
        url = source.assetPath;
        break;
      case 'file':
        url = source.filePath;
        break;
      case 'memory':
        if (source.bytes instanceof Uint8Array) {
          const blob = new Blob([source.bytes], { type: 'application/pdf' });
          url = URL.createObjectURL(blob);
        }
        break;
    }

    if (!url) {
      throw new Error('Could not resolve PDF source');
    }

    // Store document reference
    documents[documentId] = {
      url: url,
      pageCount: 1, // Default — browser PDF viewer handles pagination
    };

    return {
      documentId: documentId,
      pageCount: 1,
    };
  }

  /**
   * Render a PDF page to RGBA pixels via canvas.
   * Web has limited native PDF rendering — this is a best-effort approach.
   * For full rendering, a library like PDF.js would be needed.
   *
   * @param {string} documentId
   * @param {number} pageIndex
   * @param {number} width
   * @param {number} height
   * @returns {Promise<{pixels: Uint8Array, width: number, height: number}|null>}
   */
  async function renderPage(documentId, pageIndex, width, height) {
    const doc = documents[documentId];
    if (!doc) return null;

    // Web fallback: return null to let Dart show a placeholder
    // Full pixel rendering requires PDF.js integration
    return null;
  }

  /**
   * Get page size (not available without PDF.js on web).
   */
  function getPageSize(documentId, pageIndex) {
    return { width: 612, height: 792 }; // US Letter default
  }

  /**
   * Search text (not available without PDF.js on web).
   */
  function searchText(documentId, query) {
    return [];
  }

  /**
   * Get the URL for embedding in an iframe.
   * This allows the browser's native PDF viewer to handle rendering.
   */
  function getDocumentUrl(documentId) {
    const doc = documents[documentId];
    return doc ? doc.url : null;
  }

  /**
   * Close a PDF document and release resources.
   */
  function close(documentId) {
    const doc = documents[documentId];
    if (doc) {
      // Revoke blob URLs to free memory
      if (doc.url && doc.url.startsWith('blob:')) {
        URL.revokeObjectURL(doc.url);
      }
      delete documents[documentId];
    }
  }

  // Expose global API
  window.CyberGuardPdf = {
    open: open,
    renderPage: renderPage,
    getPageSize: getPageSize,
    searchText: searchText,
    getDocumentUrl: getDocumentUrl,
    close: close,
  };
})();
