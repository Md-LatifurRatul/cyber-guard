import 'package:flutter/material.dart';

import '../../ui/secure_content_widget.dart';
import '../../ui/security_status_bar.dart';

/// Full-screen secure content viewer with all CyberGuard protections active.
///
/// ## Protection layers applied:
/// 1. Native secure mode (FLAG_SECURE / NSWindow.sharingType)
/// 2. Visible watermark overlay (email/name/timestamp)
/// 3. Blur shield on threat detection
/// 4. Security status indicator
///
/// ## Usage:
/// ```dart
/// Navigator.push(context, MaterialPageRoute(
///   builder: (_) => SecureViewerScreen(
///     title: 'Confidential Report',
///     child: Image.network(url),
///   ),
/// ));
/// ```
///
/// The screen automatically enters secure mode when pushed onto the
/// navigator stack and exits when popped. No manual lifecycle management
/// needed by the caller.
class SecureViewerScreen extends StatelessWidget {
  const SecureViewerScreen({
    super.key,
    required this.child,
    this.title = 'Secure Content',
    this.showStatusBar = true,
    this.backgroundColor,
  });

  /// The secure content to display (image, video, document, etc.).
  final Widget child;

  /// Title shown in the app bar.
  final String title;

  /// Whether to show the SecurityStatusBar in the app bar.
  final bool showStatusBar;

  /// Background color. Defaults to theme scaffold background.
  final Color? backgroundColor;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: backgroundColor,
      appBar: AppBar(
        title: Text(title),
        actions: [
          if (showStatusBar)
            const Padding(
              padding: EdgeInsets.only(right: 8),
              child: SecurityStatusBar(compact: true),
            ),
        ],
      ),
      body: SecureContentWidget(
        child: child,
      ),
    );
  }
}

/// A demo screen showcasing all security layers with sample content.
///
/// Used during development and testing to verify:
/// - Watermark renders correctly with user info
/// - Blur activates on security events
/// - Security status updates in real-time
/// - Navigation lifecycle (enter/exit secure mode)
class SecureViewerDemo extends StatelessWidget {
  const SecureViewerDemo({super.key});

  @override
  Widget build(BuildContext context) {
    return SecureViewerScreen(
      title: 'Protected Document',
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Security status panel
            const SecurityStatusBar(),
            const SizedBox(height: 24),

            // Simulated confidential content
            _buildContentCard(
              context,
              title: 'Confidential Report',
              content: 'This content is protected by CyberGuard\'s '
                  'defense-in-depth security framework.\n\n'
                  'Multiple layers of protection are active:\n'
                  '- Native screen capture prevention\n'
                  '- Visible forensic watermark\n'
                  '- Real-time threat monitoring\n'
                  '- Blur shield on capture detection\n\n'
                  'Try taking a screenshot or screen recording to see '
                  'the protection in action.',
            ),
            const SizedBox(height: 16),

            _buildContentCard(
              context,
              title: 'Secure Image',
              child: Container(
                height: 200,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(8),
                  gradient: const LinearGradient(
                    colors: [
                      Color(0xFF1A237E),
                      Color(0xFF283593),
                      Color(0xFF3949AB),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: const Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.lock, size: 48, color: Colors.white70),
                      SizedBox(height: 8),
                      Text(
                        'Protected Content Area',
                        style: TextStyle(
                          color: Colors.white70,
                          fontSize: 16,
                        ),
                      ),
                      SizedBox(height: 4),
                      Text(
                        'Watermark visible in captures',
                        style: TextStyle(
                          color: Colors.white38,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            const SizedBox(height: 16),

            _buildContentCard(
              context,
              title: 'Financial Data',
              content: 'Account Balance: \$42,857.93\n'
                  'Transaction ID: TXN-2024-0847291\n'
                  'IBAN: DE89 3704 0044 0532 0130 00\n'
                  'Routing: 021000021\n\n'
                  'This sensitive financial data is protected from '
                  'screen capture and recording.',
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  Widget _buildContentCard(
    BuildContext context, {
    required String title,
    String? content,
    Widget? child,
  }) {
    final theme = Theme.of(context);
    return Card(
      elevation: 2,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.lock_outline,
                  size: 16,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: 6),
                Text(
                  title,
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            if (content case final text?)
              Text(
                text,
                style: theme.textTheme.bodyMedium?.copyWith(
                  height: 1.5,
                ),
              ),
            ?child,
          ],
        ),
      ),
    );
  }
}
