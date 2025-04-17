import 'dart:convert';
import 'package:http/http.dart' as http;

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
