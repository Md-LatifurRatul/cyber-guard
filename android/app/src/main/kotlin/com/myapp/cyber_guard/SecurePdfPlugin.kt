package com.myapp.cyber_guard

import android.content.Context
import android.graphics.Bitmap
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import kotlinx.coroutines.*
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.util.UUID

/**
 * Secure PDF Plugin for Android.
 *
 * Uses Android's [PdfRenderer] API to render PDF pages as RGBA pixel data.
 * The Dart side receives raw pixels and displays them via [RawImage].
 *
 * ## MethodChannel: "com.cyberguard.security/pdf"
 *
 * ## Methods:
 * - open(source) → {documentId, pageCount}
 * - renderPage(documentId, pageIndex, width, height) → {pixels, width, height}
 * - getPageSize(documentId, pageIndex) → {width, height}
 * - searchText(documentId, query) → [{page, text}]  (basic — PdfRenderer has no text API)
 * - close(documentId)
 */
class SecurePdfPlugin : FlutterPlugin, MethodCallHandler {

    companion object {
        private const val TAG = "CyberGuard:PDF"
        private const val CHANNEL_NAME = "com.cyberguard.security/pdf"
    }

    private var channel: MethodChannel? = null
    private var context: Context? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /** Active PDF documents (documentId → PdfDocument) */
    private val documents = mutableMapOf<String, PdfDocument>()

    // ─── FlutterPlugin ───

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL_NAME).also {
            it.setMethodCallHandler(this)
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel?.setMethodCallHandler(null)
        channel = null
        context = null
        // Close all open documents
        documents.values.forEach { it.close() }
        documents.clear()
        scope.cancel()
    }

    // ─── MethodCallHandler ───

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "open" -> handleOpen(call, result)
            "renderPage" -> handleRenderPage(call, result)
            "getPageSize" -> handleGetPageSize(call, result)
            "searchText" -> handleSearchText(call, result)
            "close" -> handleClose(call, result)
            else -> result.notImplemented()
        }
    }

    // ─── Open ───

    private fun handleOpen(call: MethodCall, result: Result) {
        val source = call.argument<Map<String, Any>>("source")
        if (source == null) {
            result.error("INVALID_ARGS", "Missing source", null)
            return
        }

        scope.launch {
            try {
                val file = resolveSourceToFile(source)
                if (file == null) {
                    withContext(Dispatchers.Main) {
                        result.error("INVALID_SOURCE", "Could not resolve PDF source", null)
                    }
                    return@launch
                }

                val fd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
                val renderer = PdfRenderer(fd)
                val documentId = UUID.randomUUID().toString()

                documents[documentId] = PdfDocument(
                    id = documentId,
                    renderer = renderer,
                    fileDescriptor = fd,
                    tempFile = if (source["type"] == "network" || source["type"] == "memory") file else null
                )

                withContext(Dispatchers.Main) {
                    result.success(
                        mapOf(
                            "documentId" to documentId,
                            "pageCount" to renderer.pageCount,
                        )
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to open PDF: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    result.error("OPEN_FAILED", e.message, null)
                }
            }
        }
    }

    // ─── Render Page ───

    private fun handleRenderPage(call: MethodCall, result: Result) {
        val documentId = call.argument<String>("documentId")
        val pageIndex = call.argument<Int>("pageIndex") ?: -1
        val width = call.argument<Int>("width") ?: 800
        val height = call.argument<Int>("height") ?: 1200

        val doc = documents[documentId]
        if (doc == null) {
            result.error("DOC_NOT_FOUND", "No document with id: $documentId", null)
            return
        }

        scope.launch {
            try {
                val page = doc.renderer.openPage(pageIndex)

                // Render to bitmap at requested dimensions
                val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                page.close()

                // Convert ARGB_8888 to RGBA bytes for Flutter
                val buffer = ByteBuffer.allocate(bitmap.byteCount)
                bitmap.copyPixelsToBuffer(buffer)
                val argbBytes = buffer.array()
                val rgbaBytes = convertArgbToRgba(argbBytes)
                bitmap.recycle()

                withContext(Dispatchers.Main) {
                    result.success(
                        mapOf(
                            "pixels" to rgbaBytes,
                            "width" to width,
                            "height" to height,
                        )
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Render error page $pageIndex: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    result.error("RENDER_FAILED", e.message, null)
                }
            }
        }
    }

    // ─── Get Page Size ───

    private fun handleGetPageSize(call: MethodCall, result: Result) {
        val documentId = call.argument<String>("documentId")
        val pageIndex = call.argument<Int>("pageIndex") ?: 0

        val doc = documents[documentId]
        if (doc == null) {
            result.error("DOC_NOT_FOUND", "No document with id: $documentId", null)
            return
        }

        try {
            val page = doc.renderer.openPage(pageIndex)
            val width = page.width.toDouble()
            val height = page.height.toDouble()
            page.close()

            result.success(
                mapOf(
                    "width" to width,
                    "height" to height,
                )
            )
        } catch (e: Exception) {
            result.error("PAGE_SIZE_FAILED", e.message, null)
        }
    }

    // ─── Search Text ───

    private fun handleSearchText(call: MethodCall, result: Result) {
        // Android PdfRenderer does not support text extraction.
        // Return empty results — text search requires a more advanced library.
        result.success(emptyList<Map<String, Any>>())
    }

    // ─── Close ───

    private fun handleClose(call: MethodCall, result: Result) {
        val documentId = call.argument<String>("documentId")
        val doc = documents.remove(documentId)
        doc?.close()
        result.success(null)
    }

    // ─── Source Resolution ───

    private suspend fun resolveSourceToFile(source: Map<String, Any>): File? {
        val type = source["type"] as? String ?: "network"
        val ctx = context ?: return null

        return when (type) {
            "network" -> {
                val url = source["url"] as? String ?: return null
                @Suppress("UNCHECKED_CAST")
                val headers = source["headers"] as? Map<String, String> ?: emptyMap()
                downloadToTemp(ctx, url, headers)
            }
            "asset" -> {
                val assetPath = source["assetPath"] as? String ?: return null
                copyAssetToTemp(ctx, assetPath)
            }
            "file" -> {
                val filePath = source["filePath"] as? String ?: return null
                File(filePath).takeIf { it.exists() }
            }
            "memory" -> {
                val bytes = source["bytes"] as? ByteArray ?: return null
                writeBytesToTemp(ctx, bytes)
            }
            else -> null
        }
    }

    private suspend fun downloadToTemp(ctx: Context, urlStr: String, headers: Map<String, String>): File? {
        return withContext(Dispatchers.IO) {
            try {
                val url = URL(urlStr)
                val conn = url.openConnection() as HttpURLConnection
                headers.forEach { (key, value) -> conn.setRequestProperty(key, value) }
                conn.connectTimeout = 30_000
                conn.readTimeout = 30_000

                val tempFile = File.createTempFile("cyberguard_pdf_", ".pdf", ctx.cacheDir)
                conn.inputStream.use { input ->
                    FileOutputStream(tempFile).use { output ->
                        input.copyTo(output)
                    }
                }
                conn.disconnect()
                tempFile
            } catch (e: Exception) {
                Log.e(TAG, "Download failed: ${e.message}", e)
                null
            }
        }
    }

    private fun copyAssetToTemp(ctx: Context, assetPath: String): File? {
        return try {
            val key = ctx.assets.openFd("flutter_assets/$assetPath")
            val tempFile = File.createTempFile("cyberguard_pdf_", ".pdf", ctx.cacheDir)
            key.createInputStream().use { input ->
                FileOutputStream(tempFile).use { output ->
                    input.copyTo(output)
                }
            }
            tempFile
        } catch (e: Exception) {
            Log.e(TAG, "Asset copy failed: ${e.message}", e)
            null
        }
    }

    private fun writeBytesToTemp(ctx: Context, bytes: ByteArray): File? {
        return try {
            val tempFile = File.createTempFile("cyberguard_pdf_", ".pdf", ctx.cacheDir)
            FileOutputStream(tempFile).use { it.write(bytes) }
            tempFile
        } catch (e: Exception) {
            Log.e(TAG, "Memory write failed: ${e.message}", e)
            null
        }
    }

    // ─── Pixel Conversion ───

    /**
     * Convert Android's ARGB_8888 to RGBA_8888 expected by Flutter.
     *
     * ARGB: [A, R, G, B] per pixel (Android native)
     * RGBA: [R, G, B, A] per pixel (Flutter ui.PixelFormat.rgba8888)
     */
    private fun convertArgbToRgba(argb: ByteArray): ByteArray {
        val rgba = ByteArray(argb.size)
        var i = 0
        while (i < argb.size) {
            rgba[i] = argb[i + 1]     // R
            rgba[i + 1] = argb[i + 2] // G
            rgba[i + 2] = argb[i + 3] // B
            rgba[i + 3] = argb[i]     // A
            i += 4
        }
        return rgba
    }
}

/**
 * Holds an open PdfRenderer and its associated resources.
 */
private data class PdfDocument(
    val id: String,
    val renderer: PdfRenderer,
    val fileDescriptor: ParcelFileDescriptor,
    val tempFile: File?,
) {
    fun close() {
        try { renderer.close() } catch (_: Exception) {}
        try { fileDescriptor.close() } catch (_: Exception) {}
        tempFile?.delete()
    }
}
