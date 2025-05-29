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

import 'package:flutter_python_bridge/flutter_python_bridge.dart';
import 'package:path_provider/path_provider.dart';

final pythonBridge = PythonBridge();

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

final Color primaryBlue = const Color(0xFF1F2A44);
final Color accentGreen = const Color(0xFF42A67F);
final Color softGray = const Color(0xFFBFC0C0);

HistoryDatabase history = HistoryDatabase();

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
    
    double score = 0;
    bool infected = false;
    int count = 1;
    final path = file.path;

    final hash = await QuarantineService.computeFileHash(file);
    if (QuarantineService.isWhitelisted(hash)) {
      print('✅ File is whitelisted. Skipping: $path');
      return;
    }

    final documentdirectory = await getApplicationDocumentsDirectory();
    final resultdirectory = '${documentdirectory.path}\\rtsfile.txt';
    String resultdirectorys = resultdirectory.toString();
    final resultdirectoryf = File(resultdirectorys);

    resultdirectoryf.writeAsString(path);

    final resultp = await pythonBridge.runScript('assets/detector/realtime.py');

    if(resultp.success){
      print(resultp);

      final documentdirectory = await getApplicationDocumentsDirectory();
      final resultdirectory = '${documentdirectory.path}\\resultrts.txt';
      String resultdirectorys = resultdirectory.toString();
      final resultdirectoryf = File(resultdirectorys);

      try {
        final lines = await resultdirectoryf.readAsLines();

        // Do something with each line
        for (final line in lines) {
          switch(count){
            case 1:
              print('Line: $line');
              score = double.parse(line);
              count++;
              break;
          }
        }

        print(path);
        print(score);

        if(score >= 0.8){

        infected = true;

        }

        if (infected) {

          if (infected) {
            final now = DateTime.now();
            history.insertHistory(1, now.month, now.day, now.hour, now.minute);

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
        
    } catch (e) {
      print('Error scanning file ${file.path}: $e');
    }
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
    String path = '';
    double score = 0;
    bool infected = false;
    int count = 1;

    setState(() {
      _isScanning = true;
      _status = "Scanning";
    });

    final resultp = await pythonBridge.runScript('assets/detector/detector.py');

    if(resultp.success){
      print(resultp);

      final documentdirectory = await getApplicationDocumentsDirectory();
      final resultdirectory = '${documentdirectory.path}\\result.txt';
      String resultdirectorys = resultdirectory.toString();
      final resultdirectoryf = File(resultdirectorys);

      try {
        final lines = await resultdirectoryf.readAsLines();

        // Do something with each line
        for (final line in lines) {
          switch(count){
            case 1:
              print('Line: $line');
              path = line;
              count++;
              break;
            case 2:
              print('Line: $line');
              score = double.parse(line);
              count++;
              break;
          }
        }

        print(path);
        print(score);

        if(score >= 0.8){

        infected = true;

        }

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

      } catch (e) {
        print('Error reading file: $e');
      }
    }else{
      setState(() {
      _isScanning = false;
      _status = "Cancelled";
      });
    }
      
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
