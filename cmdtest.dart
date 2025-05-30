import 'dart:io';

void main() async {
  print('Starting Ollama detector test...');

  // Replace this with the correct relative or absolute path
  final scriptPath = 'backend/ai_powered_detector.py';
  final sampleFile = 'ai_detector_demo/ai_generated/ai_malware_sample.py';

  final result = await Process.run('python', [scriptPath, sampleFile]);

  print('stdout:\n${result.stdout}');
  print('stderr:\n${result.stderr}');
  print('Exit code: ${result.exitCode}');
}
