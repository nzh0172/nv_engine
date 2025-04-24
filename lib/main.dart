import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:nv_engine/theme/theme_provider.dart';
import 'package:nv_engine/pages/home_page.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:nv_engine/services/tflite_service.dart';  // Add this import
import 'package:flutter/services.dart';



void main() async {
  WidgetsFlutterBinding.ensureInitialized();  // Required for initialization

  sqfliteFfiInit();

  databaseFactory = databaseFactoryFfi;

    // Initialize TFLite model

    try {
    final data = await rootBundle.load('assets/model.tflite');
    print("✅ model.tflite found, size: ${data.lengthInBytes} bytes");
  } catch (e) {
    print("🛑 model.tflite NOT found: $e");
  }
  await TFLiteService.loadModel();

  runApp(
    ChangeNotifierProvider(
      create: (context) => ThemeProvider(),
      child: const AntivirusApp(),
    ),
  );
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
