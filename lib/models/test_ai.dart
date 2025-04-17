import 'package:flutter/material.dart';
import 'package:nv_engine/ai_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized(); // Needed for rootBundle

  // Dummy input (entropy, packed, api_count, max_entropy)
  List<double> testInput = [7.9, 1.0, 3.0, 7.2];

  await runMalwarePrediction(testInput);
}
