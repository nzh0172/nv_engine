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
      theme: ThemeData(
        primaryColor: Color(0xFF1F2A44),
        scaffoldBackgroundColor: Color(0xFFF5F5F5),
        fontFamily: 'Roboto',
      ),
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
  bool _realTimeProtectionEnabled = true;
  bool _notificationsEnabled = true;
  bool _darkModeEnabled = false;
  int _selectedIndex = 0;
  String _status = "Ready to scan!";
  bool _isScanning = false;

  Future<void> _startScan() async {
    setState(() {
      _isScanning = true;
      _status = "Scanning... Please wait.";
    });

    await Future.delayed(Duration(seconds: 3), () {
      setState(() {
        _isScanning = false;
        _status = "Scan Complete! No threats detected.";
      });
    });
  }

  final Color primaryBlue = Color(0xFF1F2A44);
  final Color accentGreen = Color(0xFF42A67F);
  final Color softGray = Color(0xFFBFC0C0);
  final Color darkText = Color(0xFF2E2E2E);

  Widget _buildPage() {
    switch (_selectedIndex) {
      case 0:
        return _buildOverviewPage();
      case 1:
        return _buildProtectionPage();
      case 2:
        return _buildSettingsPage();
      default:
        return _buildOverviewPage();
    }
  }

  Widget _buildOverviewPage() {
    return LayoutBuilder(
      builder: (context, constraints) {
        double iconSize = constraints.maxHeight * 0.2;

        return Padding(
          padding: const EdgeInsets.all(40.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: <Widget>[
              Icon(Icons.shield, size: iconSize.clamp(120.0, 300.0), color: accentGreen),
          SizedBox(height: 20),
          Text(
            _status,
            style: TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.bold,
              color: _status.contains("No threats")
                  ? accentGreen
                  : (_status.contains("Ready")
                      ? darkText
                      : Colors.orange),
            ),
            textAlign: TextAlign.center,
          ),
          SizedBox(height: 10),
          Text(
            'Last scanned: Never',
            style: TextStyle(fontSize: 14, color: softGray),
          ),
          SizedBox(height: 30),
          ElevatedButton(
            onPressed: _isScanning ? null : _startScan,
            style: ElevatedButton.styleFrom(
              backgroundColor: accentGreen,
              padding: EdgeInsets.symmetric(horizontal: 40, vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: Text(
              _isScanning ? "Scanning..." : "Start Scan",
              style: TextStyle(fontSize: 18, color: Colors.white),
            ),
          ),
        ],
      ),
        );
      },
    );
  }
  
  Widget _buildProtectionPage() {
    return LayoutBuilder(
      builder: (context, constraints) {
        return SingleChildScrollView(
          padding: const EdgeInsets.all(40.0),
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: constraints.maxHeight),
            child: IntrinsicHeight(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text("Protection Settings",
                      style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: darkText)),
                  SizedBox(height: 30),

                  if (!_realTimeProtectionEnabled)
                    Container(
                      width: double.infinity,
                      padding: EdgeInsets.all(16),
                      margin: EdgeInsets.only(bottom: 20),
                      decoration: BoxDecoration(
                        color: Colors.red.shade100,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Row(
                        children: [
                          Icon(Icons.warning, color: Colors.red),
                          SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              "Warning: Real-Time Protection is disabled. Your system might be at risk.",
                              style: TextStyle(color: Colors.red, fontWeight: FontWeight.bold),
                            ),
                          ),
                        ],
                      ),
                    ),

                  SwitchListTile(
                    value: _realTimeProtectionEnabled,
                    onChanged: (val) {
                      setState(() {
                        _realTimeProtectionEnabled = val;
                      });
                    },
                    title: Text("Enable Real-Time Protection"),
                  ),

                  ListTile(
                    leading: Icon(Icons.shield, color: accentGreen),
                    title: Text("Firewall: Active"),
                    subtitle: Text("Your system is protected from network threats."),
                  ),

                  ExpansionTile(
                    leading: Icon(Icons.warning_amber, color: Colors.red),
                    title: Text("Threats Blocked: 5"),
                    subtitle: Text("Last 30 days"),
                    children: [
                      SizedBox(
                        height: 150,
                        child: ListView(
                          shrinkWrap: true,
                          children: [
                            ListTile(
                              title: Text("Malware.ABC"),
                              subtitle: Text("Blocked on Apr 1"),
                              trailing: ElevatedButton(
                                onPressed: () {},
                                child: Text("Details"),
                              ),
                            ),
                            ListTile(
                              title: Text("Trojan.XYZ"),
                              subtitle: Text("Blocked on Mar 30"),
                              trailing: ElevatedButton(
                                onPressed: () {},
                                child: Text("Details"),
                              ),
                            ),
                            ListTile(
                              title: Text("Spyware.123"),
                              subtitle: Text("Blocked on Mar 27"),
                              trailing: ElevatedButton(
                                onPressed: () {},
                                child: Text("Details"),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),

                  SizedBox(height: 20),
                  ElevatedButton.icon(
                    onPressed: _isScanning ? null : _startScan,
                    icon: Icon(Icons.search, color: Colors.white),
                    label: Text("Run Quick Scan", style: TextStyle(fontSize: 18, color: Colors.white)),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: accentGreen,
                      padding: EdgeInsets.symmetric(horizontal: 40, vertical: 16),
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

  Widget _buildSettingsPage() {
    return Padding(
      padding: const EdgeInsets.all(40.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text("Settings", style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: darkText)),
          SizedBox(height: 20),
          SwitchListTile(
            value: _notificationsEnabled,
            onChanged: (val) {
              setState(() {
                _notificationsEnabled = val;
              });
            },
            title: Text("Enable Notifications"),
          ),
          SwitchListTile(
            value: _darkModeEnabled,
            onChanged: (val) {
              setState(() {
                _darkModeEnabled = val;
              });
            },
            title: Text("Dark Mode"),
          ),
        ],
      ),
    );
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

class NavigationPanel extends StatelessWidget {
  final Color backgroundColor;
  final int selectedIndex;
  final Function(int) onItemSelected;

  NavigationPanel({
    required this.backgroundColor,
    required this.selectedIndex,
    required this.onItemSelected,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 200,
      color: backgroundColor,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DrawerHeader(
            child: Text(
              'NV Engine',
              style: TextStyle(color: Colors.white, fontSize: 24),
            ),
          ),
          NavItem(icon: Icons.dashboard, label: 'Overview', selected: selectedIndex == 0, onTap: () => onItemSelected(0)),
          NavItem(icon: Icons.security, label: 'Protection', selected: selectedIndex == 1, onTap: () => onItemSelected(1)),
          NavItem(icon: Icons.settings, label: 'Settings', selected: selectedIndex == 2, onTap: () => onItemSelected(2)),
        ],
      ),
    );
  }
}

class NavItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  NavItem({required this.icon, required this.label, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: selected ? Colors.white.withOpacity(0.1) : Colors.transparent,
      child: ListTile(
        leading: Icon(icon, color: Colors.white),
        title: Text(
          label,
          style: TextStyle(color: Colors.white),
        ),
        onTap: onTap,
      ),
    );
  }
}
