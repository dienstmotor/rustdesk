import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';
import 'package:url_launcher/url_launcher.dart';

/// Dienstmotor operator sign-in state, mirrored from Rust (`dienstmotor_auth::status`).
/// Rust owns the session and enforces it on every new connection; this only drives the UI.
class DmAuth {
  static final state = 'unauthenticated'.obs;
  static final username = ''.obs;
  static final name = ''.obs;
  static final error = ''.obs;
  static Timer? _timer;

  static bool get isAuthenticated => state.value == 'authenticated';

  static void refresh() {
    try {
      final m = jsonDecode(bind.mainDmAuthStatus()) as Map<String, dynamic>;
      state.value = m['state'] ?? 'unauthenticated';
      username.value = m['username'] ?? '';
      name.value = m['name'] ?? '';
      error.value = m['error'] ?? '';
    } catch (e) {
      debugPrint('DmAuth status: $e');
    }
  }

  static void startPolling() {
    refresh();
    _timer ??= Timer.periodic(const Duration(seconds: 2), (_) => refresh());
  }

  static Future<void> login() async {
    final m = jsonDecode(await bind.mainDmAuthLogin()) as Map<String, dynamic>;
    refresh();
    final url = m['url'] as String?;
    if (url == null || url.isEmpty) {
      showToast(translate(m['error'] ?? 'Error'));
      return;
    }
    if (!await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication)) {
      showToast(translate('Error'));
    }
  }

  static void logout() {
    bind.mainDmAuthLogout();
    refresh();
  }

  /// Gate for starting a new connection from the UI.
  static bool allowsConnect() {
    refresh();
    if (!isAuthenticated) {
      showToast(translate('Sign-in required to control another device'));
      return false;
    }
    return true;
  }
}

class DmAuthPanel extends StatefulWidget {
  const DmAuthPanel({Key? key}) : super(key: key);

  @override
  State<DmAuthPanel> createState() => _DmAuthPanelState();
}

class _DmAuthPanelState extends State<DmAuthPanel> {
  @override
  void initState() {
    super.initState();
    DmAuth.startPolling();
  }

  @override
  Widget build(BuildContext context) {
    final hint = Theme.of(context).textTheme.bodySmall;
    return Obx(() {
      final err = DmAuth.error.value;
      final Widget body;
      switch (DmAuth.state.value) {
        case 'authenticated':
          final who = DmAuth.name.value.isNotEmpty
              ? DmAuth.name.value
              : DmAuth.username.value;
          body = Row(children: [
            const Icon(Icons.verified_user, size: 16, color: Colors.green),
            const SizedBox(width: 6),
            Expanded(
              child: Text('${translate('Signed in as')} $who',
                  overflow: TextOverflow.ellipsis),
            ),
            TextButton(
                onPressed: DmAuth.logout, child: Text(translate('Sign out'))),
          ]);
          break;
        case 'authenticating':
          body = Row(children: [
            const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(strokeWidth: 2)),
            const SizedBox(width: 8),
            Expanded(
                child: Text(translate('Waiting for sign-in in the browser'))),
          ]);
          break;
        default:
          body = Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(translate('Sign-in required to control another device'),
                style: hint),
            const SizedBox(height: 6),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                icon: const Icon(Icons.login, size: 16),
                onPressed: DmAuth.login,
                label: Text(translate('Sign in with Dienstmotor')),
              ),
            ),
          ]);
      }
      return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        body,
        if (err.isNotEmpty && !DmAuth.isAuthenticated)
          Text(translate(err),
                  style: hint?.copyWith(color: Theme.of(context).colorScheme.error))
              .marginOnly(top: 4),
      ]);
    });
  }
}
