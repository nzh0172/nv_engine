import 'dart:convert';
import 'package:http/http.dart' as http;
import 'dart:io';

Future<int> runMalwarePrediction(List<double> inputValues) async {
  final uri = Uri.parse(
    "http://127.0.0.1:5000/predict",
  ); // or use your IP if on real device

  final response = await http.post(
    uri,
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({"input": inputValues}),
  );

  if (response.statusCode == 200) {
    final result = jsonDecode(response.body);
    return result["prediction"];
  } else {
    throw Exception("Prediction failed: ${response.body}");
  }
}

Future<Map<String, dynamic>?> runLlamaDetector(String filePath) async {
  print('🚀 Running Ollama detector on $filePath');

  try {
    final result = await Process.run(
      'python3', // or 'python' on Windows
      ['backend/ai_powered_detector.py', filePath],
    );

    if (result.exitCode != 0) {
      print('❌ Ollama subprocess error:\n${result.stderr}');
      return null;
    }

    // Find the final JSON result at the end of the stdout, if any
    final output = result.stdout.toString();

    print('📤 Raw subprocess output:\n$output');

    // OPTIONAL: You must format `ai_powered_detector.py` to print a JSON at the end:
    // Example in Python:
    // print(json.dumps(result)) ← Add to Python script

    // Example parsing (if JSON is printed):
    final jsonStart = output.lastIndexOf('{');
    if (jsonStart != -1) {
      final jsonString = output.substring(jsonStart);
      return jsonDecode(jsonString);
    }

    return null;
  } catch (e) {
    print('❌ Failed to run Ollama detector: $e');
    return null;
  }
}
