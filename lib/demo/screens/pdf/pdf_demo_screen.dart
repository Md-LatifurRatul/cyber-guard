import 'package:flutter/material.dart';

import '../../../api/models/media_source.dart';
import '../../../api/secure_pdf_viewer.dart';
import '../../theme/app_theme.dart';
import '../../widgets/glass_card.dart';

/// Demo screen showcasing the secure PDF viewer.
class PdfDemoScreen extends StatelessWidget {
  const PdfDemoScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: const Text('Secure PDF'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_rounded, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: Container(
        decoration: const BoxDecoration(gradient: AppTheme.backgroundGradient),
        child: SafeArea(
          child: Column(
            children: [
              // Info banner
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                child: GlassCard(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(
                        Icons.picture_as_pdf_rounded,
                        size: 18,
                        color: Colors.redAccent.shade100,
                      ),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text(
                          'PDF rendered via native API with watermark protection',
                          style: TextStyle(
                            fontSize: 12,
                            color: AppTheme.textSecondary,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              // PDF viewer
              Expanded(
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(12),
                  child: SecurePdfViewer(
                    source: const PdfSource.network(
                      'https://www.africau.edu/images/default/sample.pdf',
                    ),
                    onError: (error) {
                      debugPrint('PDF error: $error');
                    },
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
