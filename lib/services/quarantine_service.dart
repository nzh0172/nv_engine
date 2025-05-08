import 'dart:io';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';
import 'package:sqflite/sqflite.dart';

class QuarantineService {
  static const String _tableName = 'quarantined_files';
  static Database? _database;
  
  // Initialize the quarantine database
  static Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDatabase();
    return _database!;
  }
  
  // Create and open the database
  static Future<Database> _initDatabase() async {
    final dbPath = await getDatabasesPath();
    final path = join(dbPath, 'quarantine.db');
    
    return await openDatabase(
      path,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE $_tableName(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT,
            quarantine_path TEXT,
            filename TEXT,
            timestamp INTEGER,
            threat_score REAL,
            file_size INTEGER
          )
        ''');
      }
    );
  }
  
  // Get the quarantine directory
  static Future<Directory> get _quarantineDir async {
    final appDir = await getApplicationDocumentsDirectory();
    final dir = Directory('${appDir.path}/quarantine');
    
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    
    return dir;
  }
  
  // Quarantine a file
  static Future<bool> quarantineFile({
    required String filePath,
    required double threatScore,
  }) async {
    try {
      final file = File(filePath);
      if (!await file.exists()) {
        throw Exception('File does not exist');
      }
      
      final filename = basename(filePath);
      final quarantineDirectory = await _quarantineDir;
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      final quarantinePath = '${quarantineDirectory.path}/$timestamp-$filename';
      
      // Copy the file to quarantine location
      await file.copy(quarantinePath);
      
      // Add entry to database
      final db = await database;
      await db.insert(_tableName, {
        'original_path': filePath,
        'quarantine_path': quarantinePath,
        'filename': filename,
        'timestamp': timestamp,
        'threat_score': threatScore,
        'file_size': await file.length(),
      });
      
      // Delete the original file
      await file.delete();
      
      return true;
    } catch (e) {
      print('Error quarantining file: $e');
      return false;
    }
  }
  
  // Get all quarantined files
  static Future<List<Map<String, dynamic>>> getQuarantinedFiles() async {
    final db = await database;
    return await db.query(_tableName, orderBy: 'timestamp DESC');
  }
  
  // Restore a file from quarantine
  static Future<bool> restoreFile(int id) async {
    try {
      final db = await database;
      final fileInfo = await db.query(
        _tableName,
        where: 'id = ?',
        whereArgs: [id],
        limit: 1,
      );
      
      if (fileInfo.isEmpty) {
        throw Exception('File not found in quarantine');
      }
      
      final originalPath = fileInfo.first['original_path'] as String;
      final quarantinePath = fileInfo.first['quarantine_path'] as String;
      
      // Check if original directory exists
      final originalDir = Directory(dirname(originalPath));
      if (!await originalDir.exists()) {
        await originalDir.create(recursive: true);
      }
      
      // Copy file back to original location
      await File(quarantinePath).copy(originalPath);
      
      // Delete quarantined file
      await File(quarantinePath).delete();
      
      // Remove from database
      await db.delete(
        _tableName,
        where: 'id = ?',
        whereArgs: [id],
      );
      
      return true;
    } catch (e) {
      print('Error restoring file: $e');
      return false;
    }
  }
  
  // Delete a quarantined file permanently
  static Future<bool> deleteQuarantinedFile(int id) async {
    try {
      final db = await database;
      final fileInfo = await db.query(
        _tableName,
        where: 'id = ?',
        whereArgs: [id],
        limit: 1,
      );
      
      if (fileInfo.isEmpty) {
        throw Exception('File not found in quarantine');
      }
      
      final quarantinePath = fileInfo.first['quarantine_path'] as String;
      
      // Delete the file
      await File(quarantinePath).delete();
      
      // Remove from database
      await db.delete(
        _tableName,
        where: 'id = ?',
        whereArgs: [id],
      );
      
      return true;
    } catch (e) {
      print('Error deleting quarantined file: $e');
      return false;
    }
  }
}