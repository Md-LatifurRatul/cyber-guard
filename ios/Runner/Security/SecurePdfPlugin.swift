import Flutter
import UIKit
import PDFKit

/// Secure PDF Plugin for iOS.
///
/// Uses PDFKit (`PDFDocument`, `PDFPage`) to render PDF pages as RGBA pixel data.
/// The Dart side receives raw pixels and displays them via `RawImage`.
///
/// ## Channel: "com.cyberguard.security/pdf"
///
/// ## Methods:
/// - open(source) → {documentId, pageCount}
/// - renderPage(documentId, pageIndex, width, height) → {pixels, width, height}
/// - getPageSize(documentId, pageIndex) → {width, height}
/// - searchText(documentId, query) → [{page, text}]
/// - close(documentId)
class SecurePdfPlugin: NSObject, FlutterPlugin {

    static let channelName = "com.cyberguard.security/pdf"

    private var channel: FlutterMethodChannel?

    /// Active PDF documents (documentId → PdfDocumentHandle)
    private var documents: [String: PdfDocumentHandle] = [:]

    // MARK: - FlutterPlugin

    static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: channelName,
            binaryMessenger: registrar.messenger()
        )
        let instance = SecurePdfPlugin()
        instance.channel = channel
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "open":
            handleOpen(call, result: result)
        case "renderPage":
            handleRenderPage(call, result: result)
        case "getPageSize":
            handleGetPageSize(call, result: result)
        case "searchText":
            handleSearchText(call, result: result)
        case "close":
            handleClose(call, result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Open

    private func handleOpen(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let sourceMap = args["source"] as? [String: Any] else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing source", details: nil))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let pdfDocument = self?.resolvePdfDocument(from: sourceMap) else {
                DispatchQueue.main.async {
                    result(FlutterError(code: "OPEN_FAILED", message: "Could not open PDF", details: nil))
                }
                return
            }

            let documentId = UUID().uuidString
            let handle = PdfDocumentHandle(document: pdfDocument)

            DispatchQueue.main.async {
                self?.documents[documentId] = handle
                result([
                    "documentId": documentId,
                    "pageCount": pdfDocument.pageCount,
                ] as [String: Any])
            }
        }
    }

    // MARK: - Render Page

    private func handleRenderPage(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let documentId = args["documentId"] as? String,
              let pageIndex = args["pageIndex"] as? Int,
              let width = args["width"] as? Int,
              let height = args["height"] as? Int else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing required parameters", details: nil))
            return
        }

        guard let handle = documents[documentId],
              let page = handle.document.page(at: pageIndex) else {
            result(FlutterError(code: "DOC_NOT_FOUND", message: "Document or page not found", details: nil))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let pageBounds = page.bounds(for: .mediaBox)

            // Create RGBA bitmap context
            let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
            guard let ctx = CGContext(
                data: nil,
                width: width,
                height: height,
                bitsPerComponent: 8,
                bytesPerRow: width * 4,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue // RGBA
            ) else {
                DispatchQueue.main.async {
                    result(FlutterError(code: "RENDER_FAILED", message: "Could not create bitmap context", details: nil))
                }
                return
            }

            // White background
            ctx.setFillColor(UIColor.white.cgColor)
            ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))

            // Scale PDF page to fit
            let scaleX = CGFloat(width) / pageBounds.width
            let scaleY = CGFloat(height) / pageBounds.height
            let scale = min(scaleX, scaleY)

            let offsetX = (CGFloat(width) - pageBounds.width * scale) / 2
            let offsetY = (CGFloat(height) - pageBounds.height * scale) / 2

            ctx.translateBy(x: offsetX, y: offsetY)
            ctx.scaleBy(x: scale, y: scale)

            // PDFPage draws with origin at bottom-left; CGContext is also bottom-left
            if let pageRef = page.pageRef {
                ctx.drawPDFPage(pageRef)
            }

            // Extract pixel data
            guard let data = ctx.data else {
                DispatchQueue.main.async {
                    result(FlutterError(code: "RENDER_FAILED", message: "No pixel data", details: nil))
                }
                return
            }

            let byteCount = width * height * 4
            let pixels = Data(bytes: data, count: byteCount)

            DispatchQueue.main.async {
                result([
                    "pixels": FlutterStandardTypedData(bytes: pixels),
                    "width": width,
                    "height": height,
                ] as [String: Any])
            }
        }
    }

    // MARK: - Get Page Size

    private func handleGetPageSize(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let documentId = args["documentId"] as? String,
              let pageIndex = args["pageIndex"] as? Int else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing parameters", details: nil))
            return
        }

        guard let handle = documents[documentId],
              let page = handle.document.page(at: pageIndex) else {
            result(FlutterError(code: "DOC_NOT_FOUND", message: "Document or page not found", details: nil))
            return
        }

        let bounds = page.bounds(for: .mediaBox)
        result([
            "width": Double(bounds.width),
            "height": Double(bounds.height),
        ] as [String: Any])
    }

    // MARK: - Search Text

    private func handleSearchText(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let documentId = args["documentId"] as? String,
              let query = args["query"] as? String else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing parameters", details: nil))
            return
        }

        guard let handle = documents[documentId] else {
            result(FlutterError(code: "DOC_NOT_FOUND", message: "Document not found", details: nil))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let selections = handle.document.findString(query, withOptions: .caseInsensitive)
            var results: [[String: Any]] = []

            for selection in selections {
                if let page = selection.pages.first {
                    let pageIndex = handle.document.index(for: page)
                    results.append([
                        "page": pageIndex,
                        "text": selection.string ?? query,
                    ])
                }
            }

            DispatchQueue.main.async {
                result(results)
            }
        }
    }

    // MARK: - Close

    private func handleClose(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let documentId = args["documentId"] as? String else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing documentId", details: nil))
            return
        }

        documents.removeValue(forKey: documentId)
        result(nil)
    }

    // MARK: - Source Resolution

    private func resolvePdfDocument(from source: [String: Any]) -> PDFDocument? {
        let type = source["type"] as? String ?? "network"

        switch type {
        case "network":
            guard let urlStr = source["url"] as? String,
                  let url = URL(string: urlStr) else { return nil }
            // Synchronous download (called on background thread)
            guard let data = try? Data(contentsOf: url) else { return nil }
            return PDFDocument(data: data)

        case "asset":
            guard let assetPath = source["assetPath"] as? String else { return nil }
            let key = FlutterDartProject.lookupKey(forAsset: assetPath)
            guard let path = Bundle.main.path(forResource: key, ofType: nil) else { return nil }
            guard let url = URL(string: "file://\(path)") else { return nil }
            return PDFDocument(url: url)

        case "file":
            guard let filePath = source["filePath"] as? String else { return nil }
            let url = URL(fileURLWithPath: filePath)
            return PDFDocument(url: url)

        case "memory":
            guard let bytes = source["bytes"] as? FlutterStandardTypedData else { return nil }
            return PDFDocument(data: bytes.data)

        default:
            return nil
        }
    }
}

/// Holds an open PDFDocument reference.
private class PdfDocumentHandle {
    let document: PDFDocument

    init(document: PDFDocument) {
        self.document = document
    }
}
