import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:nv_engine/theme/theme_provider.dart';
import 'package:nv_engine/pages/home_page.dart';

void main() {
  runApp(ChangeNotifierProvider(
    create: (context) => ThemeProvider(),
    child: const AntivirusApp(),
  ));
}

class AntivirusApp extends StatelessWidget {
  const AntivirusApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NV Engine',
      theme: Provider.of<ThemeProvider>(context).themeData,
      home: const AntivirusHomePage(),
    );
  }
}
