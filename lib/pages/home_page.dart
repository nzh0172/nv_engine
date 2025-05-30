// lib/pages/home_page.dart

import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:nv_engine/models/scan_result.dart';
import 'package:path/path.dart';
import 'package:provider/provider.dart';
import 'package:nv_engine/theme/theme_provider.dart';
import 'package:nv_engine/widgets/navigation_panel.dart';
import 'package:nv_engine/utils.dart';
import 'package:nv_engine/models/mock_file.dart';

import 'package:nv_engine/history_database.dart';
import 'package:nv_engine/ai_service.dart';
import 'package:nv_engine/services/tflite_service.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:watcher/watcher.dart';

import 'package:nv_engine/services/quarantine_service.dart';
import 'package:nv_engine/pages/quarantine_page.dart';

class AntivirusHomePage extends StatefulWidget {
  const AntivirusHomePage({super.key});

  @override
  _AntivirusHomePageState createState() => _AntivirusHomePageState();
}

late bool _realTimeProtectionEnabled;

Future<void> getRealTimeScan() async {
  final SharedPreferences prefs = await SharedPreferences.getInstance();

  final bool? rts = prefs.getBool('realTimeScan');

  if (rts == true) {
    _realTimeProtectionEnabled = true;
  } else {
    _realTimeProtectionEnabled = false;
  }
}

Future<void> setRealTimeScan(bool choice) async {
  final SharedPreferences prefs = await SharedPreferences.getInstance();

  await prefs.setBool('realTimeScan', choice);

  _realTimeProtectionEnabled = choice;
}

typedef MenuEntry = DropdownMenuEntry<String>;
const List<String> scheduledscan = <String>['Never', 'Daily', 'Monthly'];
late String _initialSchedule;

final List<MenuEntry> menuEntries = UnmodifiableListView<MenuEntry>(
  scheduledscan.map<MenuEntry>(
    (String name) => MenuEntry(value: name, label: name),
  ),
);
String dropdownValue = scheduledscan.first;

double _scaleSize(int bytes) => (bytes / 10000000).clamp(0.0, 1.0);
double _scaleEntropy(double e) => (e / 8).clamp(0.0, 1.0);
double _scaleImports(int n) => (n / 150).clamp(0.0, 1.0);
double _scaleStringScore(double s) => s.clamp(0.0, 1.0);

final Color primaryBlue = const Color(0xFF1F2A44);
final Color accentGreen = const Color(0xFF42A67F);
final Color softGray = const Color(0xFFBFC0C0);

HistoryDatabase history = HistoryDatabase();

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
  return e; // 0‑8
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
  final ddOffset =
      magic ==
              0x20B // PE32+
          ? optHeaderOffset + 112
          : optHeaderOffset + 96;

  // Import Table RVA & size (directory[1])
  final importRVA = data.getUint32(ddOffset + 8, Endian.little);
  if (importRVA == 0) return 0; // no imports

  // Locate section containing the import table
  final sectionTable = optHeaderOffset + optHeaderSize;
  for (int i = 0; i < numSections; i++) {
    final sOff = sectionTable + i * 40;
    final virtAddr = data.getUint32(sOff + 12, Endian.little);
    final rawSize = data.getUint32(sOff + 16, Endian.little);
    final rawPtr = data.getUint32(sOff + 20, Endian.little);

    if (importRVA >= virtAddr && importRVA < virtAddr + rawSize) {
      // Convert RVA to file offset
      final importOff = rawPtr + (importRVA - virtAddr);
      int count = 0;
      int descOff = importOff;

      // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; last descriptor is all‑zeroes
      while (descOff + 20 <= bytes.length) {
        final origFirstThunk = data.getUint32(descOff, Endian.little);
        final nameRVA = data.getUint32(descOff + 12, Endian.little);
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
  'virtualalloc',
  'writeprocessmemory',
  'loadlibrary',
  'getprocaddress',
  'createservice',
  'internetopen',
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
  return hits / strings.length; // 0‑1
}

Future<void> getSchedule() async {
  final SharedPreferences prefs = await SharedPreferences.getInstance();

  final int? schedule = prefs.getInt('schedule');

  if (schedule == 2) {
    _initialSchedule = 'Daily';
  } else if (schedule == 3) {
    _initialSchedule = 'Monthly';
  } else {
    _initialSchedule = 'Never';
  }
}

void startSafeSystemWatcher() {
  //Fixed hardcoded path
  final String homeDir =
      Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'] ?? '';

  final List<String> roots =
      Platform.isWindows
          ? ['$homeDir\\Downloads'] // This works for any Windows user
          : ['$homeDir/Downloads']; // macOS/Linux Downloads folder

  for (final root in roots) {
    _attachWatchersRecursively(Directory(root));
  }
}

void _attachWatchersRecursively(Directory dir) {
  try {
    // Try to attach a watcher to this directory
    final watcher = DirectoryWatcher(
      dir.path,
      pollingDelay: Duration(seconds: 5),
    );
    print('✅ Watching: ${dir.path}');

    watcher.events.listen((event) {
      if (_realTimeProtectionEnabled == true) {
        if (event.type == ChangeType.ADD || event.type == ChangeType.MODIFY) {
          print('📂 File changed: ${event.path}');
          _realTimeScan(File(event.path)); // Your existing scan logic
        }
      }
    });
  } catch (e) {
    print('⛔ Skipped inaccessible directory: ${dir.path}\nReason: $e');
    return;
  }

  // Recursively attempt to watch subdirectories
  try {
    final children = dir.listSync();
    for (final entity in children) {
      if (entity is Directory) {
        _attachWatchersRecursively(entity);
      }
    }
  } catch (e) {
    print('⛔ Failed to read children of ${dir.path}\nReason: $e');
  }
}

Future<void> _realTimeScan(File file) async {
  try {
    final path = file.path;
    final bytes = await file.readAsBytes();
    final sizeRaw = bytes.length;
    final entropyRaw = _calcEntropy(bytes);
    final importRaw = countImportsFromPE(path);
    final strScoreRaw = _stringScore(bytes);

    // Check file against whitelist first
    final hash = await QuarantineService.computeFileHash(file);
    if (QuarantineService.isWhitelisted(hash)) {
      print('✅ File is whitelisted. Skipping: $path');
      return;
    }

    final features = Float32List.fromList([
      _scaleSize(sizeRaw),
      _scaleEntropy(entropyRaw),
      _scaleImports(importRaw),
      _scaleStringScore(strScoreRaw),
    ]);

    final score = await TFLiteService.runMalwarePrediction(features);
    final infected = score >= 0.5;
    final confidence = (score * 100).toStringAsFixed(1);

    bool finalDecision = infected;
    String explanation = '';

    final ollamaResult = await runLlamaDetector(file.path);
    if (ollamaResult != null) {
      final verdict = ollamaResult['final_verdict'];
      final conf = ollamaResult['confidence'];
      final expl = ollamaResult['ai_analysis']['explanation'];
      explanation = expl;

      print("🧠 Ollama Result: $ollamaResult");

      if (verdict == 'MALICIOUS' || conf >= 0.7) {
        print('🛑 Ollama flagged this file!');
        finalDecision = true;
      }
    }

    print(
      '🛠️ Scanned ${basename(path)}: ${finalDecision ? '🛑 Infected' : '✅ Clean'} ($confidence%)',
    );

    // optionally log to history
    if (finalDecision) {
      final now = DateTime.now();
      history.insertHistory(1, now.month, now.day, now.hour, now.minute);

      print("🧠 Ollama Response:\n$explanation");

      final quarantineSuccess = await QuarantineService.quarantineFile(
        filePath: path,
        threatScore: score,
      );

      if (quarantineSuccess) {
        print('File quarantined: $path');
      } else {
        print('Failed to quarantine file: $path');
      }
    }
    final quarantineSuccess = await QuarantineService.quarantineFile(
      filePath: path,
      threatScore: score,
    );

    if (quarantineSuccess) {
      print('File quarantined: $path');
    } else {
      print('Failed to quarantine file: $path');
    }
  } catch (e) {
    print('Error scanning file ${file.path}: $e');
  }
}

class _AntivirusHomePageState extends State<AntivirusHomePage> {
  bool _notificationsEnabled = true;
  int _selectedIndex = 0;
  String _status = "Ready to scan!";
  bool _isScanning = false;
  List<ScanResult> _scanHistory = [];
  static bool _darkModeEnabled = false;

  Future<void> _startScan() async {
    int threats = 0;

    FilePickerResult? fresult = await FilePicker.platform.pickFiles(
      allowMultiple: true,
      type: FileType.any,
    );

    if (fresult == null) return;

    final paths = fresult.paths.whereType<String>().toList();

    for (final path in paths) {
      setState(() => _status = 'Scanning ${basename(path)}…');

      final bytes = await File(path).readAsBytes();
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

      final infected = score >= 0.5; // threshold
      print(score);
      final confidence = (score * 100).toStringAsFixed(1);
      final statusTxt = infected ? '🛑 Infected' : '✅ Clean';
      print('- ${basename(path)}: $statusTxt ($confidence %)');

      if (infected) {
        threats++;

        // Quarantine infected files
        final quarantineSuccess = await QuarantineService.quarantineFile(
          filePath: path,
          threatScore: score,
        );

        if (quarantineSuccess) {
          print('File quarantined: $path');
        } else {
          print('Failed to quarantine file: $path');
        }
      }
    }

    final result =
        threats == 0
            ? "No threats detected."
            : "$threats threat${threats > 1 ? 's' : ''} detected.";

    final newResult = ScanResult(amount: threats);

    final now = DateTime.now();
    int nowm = now.month;
    int nowd = now.day;
    int nowh = now.hour;
    int nowmin = now.minute;

    history.insertHistory(threats, nowm, nowd, nowh, nowmin);

    _scanHistory.add(newResult);

    setState(() {
      _isScanning = false;
      _status = "Scan Complete! $result";
    });
  }

  Widget _buildOverviewPage() {
    return LayoutBuilder(
      builder: (BuildContext context, constraints) {
        double iconSize = constraints.maxHeight * 0.2;

        return Padding(
          padding: const EdgeInsets.all(40.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.shield,
                size: iconSize.clamp(120.0, 300.0),
                color: accentGreen,
              ),
              const SizedBox(height: 20),
              Text(
                _status,
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                  color:
                      _status.contains("No threats")
                          ? accentGreen
                          : (_status.contains("Ready")
                              ? Theme.of(context).textTheme.headlineLarge?.color
                              : Colors.orange),
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 10),
              FutureBuilder(
                future: history.getHistory(),
                builder: (BuildContext context, AsyncSnapshot snapshot) {
                  if (snapshot.connectionState == ConnectionState.waiting) {
                    return Center(child: CircularProgressIndicator());
                  } else if (snapshot.hasError) {
                    return Text('Error: ${snapshot.error}');
                  } else if (snapshot.data == null || snapshot.data.isEmpty) {
                    return Center(child: Text('No scan history'));
                  } else {
                    return Text(
                      'Last scan on: ${snapshot.data?[snapshot.data!.length - 1]['month']}/${snapshot.data?[snapshot.data!.length - 1]['day']} ${snapshot.data?[snapshot.data!.length - 1]['hour']}:${snapshot.data?[snapshot.data!.length - 1]['minute'] < 10 ? '0${snapshot.data?[snapshot.data!.length - 1]['minute']}' : '${snapshot.data?[snapshot.data!.length - 1]['minute']}'}',
                    );
                  }
                },
              ),
              const SizedBox(height: 30),
              ElevatedButton(
                onPressed: _isScanning ? null : _startScan,
                style: ElevatedButton.styleFrom(
                  backgroundColor: accentGreen,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 40,
                    vertical: 16,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: Text(
                  _isScanning ? "Scanning..." : "Start Scan",
                  style: const TextStyle(fontSize: 18, color: Colors.white),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildProtectionPage() {
    Future<void> changeSchedule(int choice) async {
      final SharedPreferences prefs = await SharedPreferences.getInstance();

      await prefs.setInt('schedule', choice);
    }

    return LayoutBuilder(
      builder: (BuildContext context, constraints) {
        return SingleChildScrollView(
          padding: const EdgeInsets.all(40.0),
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: constraints.maxHeight),
            child: IntrinsicHeight(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    "Protection Settings",
                    style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 30),

                  if (!_realTimeProtectionEnabled)
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      margin: const EdgeInsets.only(bottom: 20),
                      decoration: BoxDecoration(
                        color: Colors.red.shade100,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.warning, color: Colors.red),
                          const SizedBox(width: 10),
                          const Expanded(
                            child: Text(
                              "Warning: Real-Time Protection is disabled. Your system might be at risk.",
                              style: TextStyle(
                                color: Colors.red,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),

                  SwitchListTile(
                    value: _realTimeProtectionEnabled,
                    onChanged: (choice) {
                      setState(() {
                        setRealTimeScan(choice);
                      });
                    },
                    title: const Text("Enable Real-Time Protection"),
                  ),

                  ListTile(
                    title: Text("Scheduled Scan"), // Text widget for the title
                    trailing: DropdownMenu(
                      requestFocusOnTap: false,
                      initialSelection: _initialSchedule,
                      onSelected: (String? value) {
                        if (value == 'Never') {
                          changeSchedule(1);
                        } else if (value == 'Daily') {
                          changeSchedule(2);
                        } else if (value == 'Monthly') {
                          changeSchedule(3);
                        }
                        setState(() {
                          dropdownValue = value!;
                        });
                      },
                      dropdownMenuEntries: menuEntries,
                    ),
                  ),

                  ListTile(
                    leading: Icon(Icons.shield, color: accentGreen),
                    title: const Text("Firewall: Active"),
                    subtitle: const Text(
                      "Your system is protected from network threats.",
                    ),
                  ),

                  ExpansionTile(
                    leading: const Icon(Icons.warning_amber, color: Colors.red),
                    title: const Text("Threats Blocked: 5"),
                    subtitle: const Text("Last 30 days"),
                    children: [
                      ListTile(
                        title: const Text("Malware.ABC"),
                        subtitle: const Text("Blocked on Apr 1"),
                        trailing: ElevatedButton(
                          onPressed: () {},
                          child: const Text("Details"),
                        ),
                      ),
                      ListTile(
                        title: const Text("Trojan.XYZ"),
                        subtitle: const Text("Blocked on Mar 30"),
                        trailing: ElevatedButton(
                          onPressed: () {},
                          child: const Text("Details"),
                        ),
                      ),
                      ListTile(
                        title: const Text("Spyware.123"),
                        subtitle: const Text("Blocked on Mar 27"),
                        trailing: ElevatedButton(
                          onPressed: () {},
                          child: const Text("Details"),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 20),
                  ElevatedButton.icon(
                    onPressed: _isScanning ? null : _startScan,
                    icon: const Icon(Icons.search, color: Colors.white),
                    label: const Text(
                      "Run Quick Scan",
                      style: TextStyle(fontSize: 18, color: Colors.white),
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: accentGreen,
                      padding: const EdgeInsets.symmetric(
                        horizontal: 40,
                        vertical: 16,
                      ),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildReportPage() {
    return Padding(
      padding: const EdgeInsets.all(40.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                "Scan Report",
                style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
              ),
              FutureBuilder<bool>(
                future: history.historyHasData(),
                builder: (BuildContext context, snapshot) {
                  switch (snapshot.connectionState) {
                    case ConnectionState.waiting:
                      return Center(child: CircularProgressIndicator());
                    default:
                      if (snapshot.hasError) {
                        return Text('Error: ${snapshot.error}');
                      } else {
                        if (snapshot.data!) {
                          return ElevatedButton.icon(
                            onPressed: () {
                              setState(() {
                                _scanHistory.clear();
                              });
                              history.clearhistory();
                            },
                            icon: const Icon(Icons.delete, color: Colors.white),
                            label: const Text(
                              "Clear",
                              style: TextStyle(color: Colors.white),
                            ),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.redAccent,
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 10,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(10),
                              ),
                            ),
                          );
                        } else {
                          return ElevatedButton.icon(
                            onPressed: null,
                            icon: const Icon(Icons.delete, color: Colors.white),
                            label: const Text(
                              "Clear",
                              style: TextStyle(color: Colors.white),
                            ),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.redAccent,
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 10,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(10),
                              ),
                            ),
                          );
                        }
                      }
                  }
                },
              ),
            ],
          ),
          const SizedBox(height: 20),
          Expanded(
            child: FutureBuilder(
              future: history.getHistory(),
              builder: (BuildContext context, AsyncSnapshot snapshot) {
                if (snapshot.connectionState == ConnectionState.waiting) {
                  return Center(child: CircularProgressIndicator());
                } else if (snapshot.hasError) {
                  return Text('Error: ${snapshot.error}');
                } else if (snapshot.data == null || snapshot.data.isEmpty) {
                  return Center(child: Text('History is empty'));
                } else {
                  return ListView.builder(
                    itemCount: snapshot.data.length,
                    itemBuilder: (BuildContext context, index) {
                      return ListTile(
                        leading: Icon(
                          snapshot.data?[index]['amount'] > 0
                              ? Icons.error
                              : Icons.check_circle,
                          color:
                              snapshot.data?[index]['amount'] > 0
                                  ? Colors.red
                                  : Colors.green,
                        ),
                        title: Text(
                          'Threat${snapshot.data?[index]['amount'] > 1 ? 's' : ''} detected: ${snapshot.data?[index]['amount']}',
                        ),
                        subtitle: Text(
                          'Scanned on: ${snapshot.data?[index]['month']}/${snapshot.data?[index]['day']} ${snapshot.data?[index]['hour']}:${snapshot.data?[index]['minute'] < 10 ? '0${snapshot.data?[index]['minute']}' : '${snapshot.data?[index]['minute']}'}',
                        ),
                      );
                    },
                  );
                }
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSettingsPage(BuildContext context) {
    final themeProvider = Provider.of<ThemeProvider>(context);

    return Padding(
      padding: const EdgeInsets.all(40.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            "Settings",
            style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 20),
          SwitchListTile(
            value: _notificationsEnabled,
            onChanged: (val) {
              setState(() {
                _notificationsEnabled = val;
              });
            },
            title: const Text("Enable Notifications"),
          ),
          SwitchListTile(
            value: themeProvider.isDarkMode,
            onChanged: (_) {
              themeProvider.toggleTheme();
            },
            title: const Text("Dark Mode"),
          ),
        ],
      ),
    );
  }

  Widget _buildPage() {
    switch (_selectedIndex) {
      case 0:
        return _buildOverviewPage();
      case 1:
        return _buildProtectionPage();
      case 2:
        return _buildReportPage();
      case 3:
        return const QuarantinePage();
      case 4:
        return _buildSettingsPage(this.context);
      default:
        return _buildOverviewPage();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          NavigationPanel(
            backgroundColor: primaryBlue,
            onItemSelected: (index) {
              setState(() {
                _selectedIndex = index;
              });
            },
            selectedIndex: _selectedIndex,
          ),
          Expanded(child: _buildPage()),
        ],
      ),
    );
  }
}
