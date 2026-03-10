import 'dart:async';

import 'package:flutter/material.dart';

import '../core/security/security_channel.dart';
import '../core/security/security_state.dart';

/// Displays real-time security status as a compact indicator bar.
///
/// Shows:
/// - Overall security status (shield icon, green/yellow/red)
/// - Active threat count and types
/// - Secure mode status
/// - Last event details (expandable)
///
/// This widget is useful for development/debugging and can be included
/// in production builds as a trust indicator for users.
class SecurityStatusBar extends StatefulWidget {
  const SecurityStatusBar({
    super.key,
    this.compact = false,
    this.showDetails = true,
  });

  /// If true, shows only the shield icon with color (no text).
  final bool compact;

  /// If true, tapping the bar expands to show detailed threat info.
  final bool showDetails;

  @override
  State<SecurityStatusBar> createState() => _SecurityStatusBarState();
}

class _SecurityStatusBarState extends State<SecurityStatusBar> {
  SecurityState _state = const SecurityState();
  StreamSubscription<SecurityState>? _subscription;
  bool _expanded = false;

  @override
  void initState() {
    super.initState();
    _state = SecurityChannel.instance.currentState;
    _subscription = SecurityChannel.instance.stateStream.listen((state) {
      setState(() => _state = state);
    });
  }

  @override
  void dispose() {
    _subscription?.cancel();
    super.dispose();
  }

  /// Determine status level from state.
  _StatusLevel get _statusLevel {
    if (!_state.isEnvironmentSafe) return _StatusLevel.critical;
    if (_state.isScreenBeingCaptured || _state.isAppBackgrounded) {
      return _StatusLevel.warning;
    }
    if (_state.isSecureModeActive) return _StatusLevel.secure;
    return _StatusLevel.inactive;
  }

  Color get _statusColor {
    return switch (_statusLevel) {
      _StatusLevel.secure => const Color(0xFF4CAF50),
      _StatusLevel.warning => const Color(0xFFFFA726),
      _StatusLevel.critical => const Color(0xFFEF5350),
      _StatusLevel.inactive => const Color(0xFF9E9E9E),
    };
  }

  IconData get _statusIcon {
    return switch (_statusLevel) {
      _StatusLevel.secure => Icons.shield,
      _StatusLevel.warning => Icons.shield_outlined,
      _StatusLevel.critical => Icons.warning_rounded,
      _StatusLevel.inactive => Icons.shield_outlined,
    };
  }

  String get _statusText {
    return switch (_statusLevel) {
      _StatusLevel.secure => 'Protected',
      _StatusLevel.warning => 'Warning',
      _StatusLevel.critical => 'Threat Detected',
      _StatusLevel.inactive => 'Inactive',
    };
  }

  @override
  Widget build(BuildContext context) {
    if (widget.compact) {
      return _buildCompactIndicator();
    }
    return _buildFullBar(context);
  }

  Widget _buildCompactIndicator() {
    return Container(
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(
        color: _statusColor.withValues(alpha: 0.15),
        shape: BoxShape.circle,
      ),
      child: Icon(_statusIcon, size: 18, color: _statusColor),
    );
  }

  Widget _buildFullBar(BuildContext context) {
    return GestureDetector(
      onTap: widget.showDetails
          ? () => setState(() => _expanded = !_expanded)
          : null,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: _statusColor.withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: _statusColor.withValues(alpha: 0.3),
          ),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header row
            Row(
              children: [
                Icon(_statusIcon, size: 20, color: _statusColor),
                const SizedBox(width: 8),
                Text(
                  _statusText,
                  style: TextStyle(
                    color: _statusColor,
                    fontWeight: FontWeight.w600,
                    fontSize: 14,
                  ),
                ),
                const Spacer(),
                if (_state.activeThreats.isNotEmpty)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 6,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: _statusColor.withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Text(
                      '${_state.activeThreats.length}',
                      style: TextStyle(
                        color: _statusColor,
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                if (widget.showDetails) ...[
                  const SizedBox(width: 4),
                  Icon(
                    _expanded
                        ? Icons.keyboard_arrow_up
                        : Icons.keyboard_arrow_down,
                    size: 18,
                    color: _statusColor.withValues(alpha: 0.6),
                  ),
                ],
              ],
            ),

            // Expanded details
            if (_expanded) ...[
              const SizedBox(height: 8),
              const Divider(height: 1),
              const SizedBox(height: 8),
              _buildDetailRow('Secure Mode', _state.isSecureModeActive),
              _buildDetailRow('Screen Capture', _state.isScreenBeingCaptured),
              _buildDetailRow('Debugger', _state.isDebuggerAttached),
              _buildDetailRow('Rooted/Jailbroken', _state.isDeviceRooted),
              _buildDetailRow('Emulator', _state.isRunningOnEmulator),
              _buildDetailRow('Hooking', _state.isHookingDetected),
              _buildDetailRow('Network MITM', _state.isNetworkIntercepted),
              _buildDetailRow('Integrity', _state.isIntegrityCompromised),
              _buildDetailRow('Memory Tamper', _state.isMemoryTampered),
              _buildDetailRow('Accessibility', _state.isAccessibilityAbused),
              _buildDetailRow('DevTools', _state.isDevToolsOpen),
              if (_state.lastEvent != null) ...[
                const SizedBox(height: 4),
                Text(
                  'Last: ${_state.lastEvent!.type.name} '
                  '(${_state.lastEvent!.severity.name})',
                  style: TextStyle(
                    fontSize: 11,
                    color: Theme.of(context)
                        .colorScheme
                        .onSurface
                        .withValues(alpha: 0.5),
                  ),
                ),
              ],
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, bool value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1),
      child: Row(
        children: [
          Icon(
            value ? Icons.circle : Icons.circle_outlined,
            size: 8,
            color: value ? Colors.red : Colors.green,
          ),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(
              fontSize: 12,
              color: value ? Colors.red : null,
            ),
          ),
        ],
      ),
    );
  }
}

enum _StatusLevel { secure, warning, critical, inactive }
