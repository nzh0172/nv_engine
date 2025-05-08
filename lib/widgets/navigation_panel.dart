// navigation_panel.dart

import 'package:flutter/material.dart';

class NavigationPanel extends StatelessWidget {
  final Color backgroundColor;
  final int selectedIndex;
  final Function(int) onItemSelected;

  const NavigationPanel({
    required this.backgroundColor,
    required this.selectedIndex,
    required this.onItemSelected,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 200,
      color: backgroundColor,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const DrawerHeader(
            child: Text(
              'NV Engine',
              style: TextStyle(color: Colors.white, fontSize: 24),
            ),
          ),
          NavItem(icon: Icons.dashboard, label: 'Overview', selected: selectedIndex == 0, onTap: () => onItemSelected(0)),
          NavItem(icon: Icons.security, label: 'Protection', selected: selectedIndex == 1, onTap: () => onItemSelected(1)),
          NavItem(icon: Icons.history, label: 'Report', selected: selectedIndex == 2, onTap: () => onItemSelected(2)),
          NavItem(icon: Icons.history, label: 'Quarantine', selected: selectedIndex == 3, onTap: () => onItemSelected(3)),
          NavItem(icon: Icons.settings, label: 'Settings', selected: selectedIndex == 4, onTap: () => onItemSelected(4)),
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

  const NavItem({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onTap,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      color: selected ? Colors.white.withOpacity(0.1) : Colors.transparent,
      child: ListTile(
        leading: Icon(icon, color: Colors.white),
        title: Text(label, style: const TextStyle(color: Colors.white)),
        onTap: onTap,
      ),
    );
  }
}

