import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:nv_engine/history_database.dart';
import 'package:path/path.dart';
import 'package:provider/provider.dart';
import 'package:nv_engine/theme/theme_provider.dart';
import 'package:nv_engine/pages/home_page.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:nv_engine/services/tflite_service.dart';  // Add this import
import 'package:flutter/services.dart';

double _scaleSize(int bytes) => (bytes / 10000000).clamp(0.0, 1.0);
double _scaleEntropy(double e) => (e / 8).clamp(0.0, 1.0);
double _scaleImports(int n) => (n / 150).clamp(0.0, 1.0);
double _scaleStringScore(double s) => s.clamp(0.0, 1.0);

double _calcEntropy(List<int> bytes) {
  final counts = List<int>.filled(256, 0);
  for (var b in bytes) counts[b]++;
  final len = bytes.length;
  double e = 0.0;
  for (var c in counts) {
    if (c == 0) continue;
    final p = c / len;
    e -= p * (log(p) / ln2);
  }
  return e;                         // 0‑8
  }

  int countImportsFromPE(String path) {
  final file = File(path);
  if (!file.existsSync()) return 0;

  final bytes = file.readAsBytesSync();
  final data = ByteData.sublistView(bytes);

  // Verify MZ header
  if (data.getUint16(0, Endian.little) != 0x5A4D) return 0;

  // PE header offset (at 0x3C)
  final peOffset = data.getUint32(0x3C, Endian.little);
  if (peOffset + 4 > bytes.length) return 0;

  // Verify "PE\0\0"
  if (data.getUint32(peOffset, Endian.little) != 0x00004550) return 0;

  // COFF header
  final numSections = data.getUint16(peOffset + 6, Endian.little);
  final optHeaderSize = data.getUint16(peOffset + 20, Endian.little);
  final optHeaderOffset = peOffset + 24;

  // Optional header: DataDirectory table starts at +96 for PE32, +112 for PE32+
  final magic = data.getUint16(optHeaderOffset, Endian.little);
  final ddOffset = magic == 0x20B             // PE32+
      ? optHeaderOffset + 112
      : optHeaderOffset + 96;

  // Import Table RVA & size (directory[1])
  final importRVA  = data.getUint32(ddOffset + 8, Endian.little);
  if (importRVA == 0) return 0; // no imports

  // Locate section containing the import table
  final sectionTable = optHeaderOffset + optHeaderSize;
  for (int i = 0; i < numSections; i++) {
    final sOff = sectionTable + i * 40;
    final virtAddr = data.getUint32(sOff + 12, Endian.little);
    final rawSize  = data.getUint32(sOff + 16, Endian.little);
    final rawPtr   = data.getUint32(sOff + 20, Endian.little);

    if (importRVA >= virtAddr && importRVA < virtAddr + rawSize) {
      // Convert RVA to file offset
      final importOff = rawPtr + (importRVA - virtAddr);
      int count = 0;
      int descOff = importOff;

      // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; last descriptor is all‑zeroes
      while (descOff + 20 <= bytes.length) {
        final origFirstThunk = data.getUint32(descOff, Endian.little);
        final nameRVA        = data.getUint32(descOff + 12, Endian.little);
        if (origFirstThunk == 0 && nameRVA == 0) break; // end
        count++;
        descOff += 20;
      }
      return count;
    }
  }
  return 0; // import section not found
  }

  final _suspectSet = <String>{
  'virtualalloc', 'writeprocessmemory', 'loadlibrary',
  'getprocaddress', 'createservice', 'internetopen',
  };

  double _stringScore(List<int> bytes) {
  final buffer = StringBuffer();
  final strings = <String>[];

  for (final b in bytes) {
    final c = b >= 32 && b <= 126 ? String.fromCharCode(b) : '\u0000';
    if (c != '\u0000') {
      buffer.write(c);
    } else if (buffer.length >= 4) {
      strings.add(buffer.toString().toLowerCase());
      buffer.clear();
    } else {
      buffer.clear();
    }
  }
  // final flush
  if (buffer.length >= 4) strings.add(buffer.toString().toLowerCase());

  if (strings.isEmpty) return 0;
  final hits = strings.where(_suspectSet.contains).length;
  return hits / strings.length;     // 0‑1
  }

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

  checkSchedule();

  getSchedule();

  getRealTimeScan();

  startSafeSystemWatcher();

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

Future<void> _scheduledScan() async {
  HistoryDatabase history = HistoryDatabase();
  
  int threats = 0;

  // Set root path for Windows or macOS
  final String rootPath = Platform.isWindows ? 'C:\\' : '/';

  final allFiles = <File>[];

  // Recursively collect all files
  void scanDirectory(Directory dir) {
    try {
      final List<FileSystemEntity> entities = dir.listSync(recursive: false);
      for (final entity in entities) {
        if (entity is File) {
          allFiles.add(entity);
        } else if (entity is Directory) {
          scanDirectory(entity); // Recurse
        }
      }
    } catch (e) {
      // Skip directories without access
      print('Skipping ${dir.path}: $e');
    }
  }

  scanDirectory(Directory(rootPath));

  // Process each file
  for (final file in allFiles) {
    final path = file.path;

    try {
      final bytes = await file.readAsBytes();
      final sizeRaw = bytes.length;
      final entropyRaw = _calcEntropy(bytes);
      final importRaw = countImportsFromPE(path);
      final strScoreRaw = _stringScore(bytes);

      final features = Float32List.fromList([
        _scaleSize(sizeRaw),
        _scaleEntropy(entropyRaw),
        _scaleImports(importRaw),
        _scaleStringScore(strScoreRaw),
      ]);

      print(features);

      await Future.delayed(const Duration(milliseconds: 600));
      final score = await TFLiteService.runMalwarePrediction(features);

      final infected = score >= 0.5;
      final confidence = (score * 100).toStringAsFixed(1);
      final statusTxt = infected ? '🛑 Infected' : '✅ Clean';
      print('- ${basename(path)}: $statusTxt ($confidence %)');

      if (infected) threats++;
    } catch (e) {
      print('Error scanning ${file.path}: $e');
    }
  }

  final now = DateTime.now();
  history.insertHistory(threats, now.month, now.day, now.hour, now.minute);

  print("finish schedule scan");
}

Future<void> checkSchedule() async {

  HistoryDatabase history = HistoryDatabase();

  final SharedPreferences prefs = await SharedPreferences.getInstance();

  final int? schedule = prefs.getInt('schedule');

  final now = DateTime.now();

  print(schedule);

  if(schedule == 2){

    int? day = await history.getDay();

    if(day != now.day){

      //_scheduledScan();

      print("daily scan");

    }

  } else if(schedule == 3){

    int? month = await history.getMonth();

    if(month != now.month){

      //_scheduledScan();

      print("monthly scan");

    }

  }
}