import 'package:flutter/material.dart';

void main() {
  runApp(AntivirusApp());
}

class AntivirusApp extends StatelessWidget {
  const AntivirusApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NV Engine',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: AntivirusHomePage(),
    );
  }
}

class AntivirusHomePage extends StatefulWidget {
  const AntivirusHomePage({super.key});

  @override
  _AntivirusHomePageState createState() => _AntivirusHomePageState();
}

class _AntivirusHomePageState extends State<AntivirusHomePage> {
  String _status = "Ready to scan!";
  bool _isScanning = false;

  // Simulate a scan process
  Future<void> _startScan() async {
    setState(() {
      _isScanning = true;
      _status = "Scanning... Please wait.";
    });

    // Simulate scan process
    await Future.delayed(Duration(seconds: 3), () {
      setState(() {
        _isScanning = false;
        // Randomly set the result
        _status =
            "Scan Complete! No threats detected."; // OR "Threat detected: Malware XYZ"
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('NV Engine')),
      drawer: Drawer(
        child: ListView(
          padding: EdgeInsets.zero,
          children: <Widget>[
            DrawerHeader(
              decoration: BoxDecoration(color: Colors.blue),
              child: Text(
                'NV Engine',
                style: TextStyle(color: Colors.white, fontSize: 24),
              ),
            ),
            ListTile(
              title: Text('Overview'),
              onTap: () {
                Navigator.pop(context);
              },
            ),
            ListTile(
              title: Text('Protection'),
              onTap: () {
                Navigator.pop(context);
              },
            ),
            ListTile(
              title: Text('Settings'),
              onTap: () {
                Navigator.pop(context);
              },
            ),
          ],
        ),
      ),
      body: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Row(
          children: <Widget>[
            // Left Navigation Bar

            // Main content area
            Expanded(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.center,
                children: <Widget>[
                  // Shield Image
                  Image.asset(
                    'assets/shield.png',
                    height: 100,
                  ), // Ensure this image exists in the assets folder
                  SizedBox(height: 20),

                  // Status Text
                  Text(
                    _status,
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color:
                          _status.contains("No threats")
                              ? Colors.green
                              : Colors.red,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  SizedBox(height: 20),

                  // Scan Button
                  ElevatedButton(
                    onPressed:
                        _isScanning
                            ? null
                            : _startScan, // Disable button if scanning
                    child: Text(_isScanning ? "Scanning..." : "Start Scan"),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
