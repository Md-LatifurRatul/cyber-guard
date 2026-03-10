import 'package:flutter_test/flutter_test.dart';

import 'package:cyber_guard/app.dart';

void main() {
  testWidgets('CyberGuardApp renders placeholder home', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const CyberGuardApp());

    expect(find.text('CyberGuard'), findsOneWidget);
    expect(find.text('Environment Secure'), findsOneWidget);
  });
}
