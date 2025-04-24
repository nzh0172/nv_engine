import 'dart:typed_data';
import 'package:tflite_flutter/tflite_flutter.dart';

class TFLiteService {
  static Interpreter? _interpreter;

  static Future<void> loadModel() async {
    try {
      _interpreter = await Interpreter.fromAsset("assets/model.tflite");
      print('✅ Model loaded successfully');

      final inputTensor = _interpreter!.getInputTensor(0);
      print('Input type: ${inputTensor.type}');
      print('Input shape: ${inputTensor.shape}');
    } catch (e) {
      print('🛑 Failed to load model: $e');
    }
  }

  static Future<double> runMalwarePrediction(List<double> features) async {
    if (_interpreter == null) {
      await loadModel();
      if (_interpreter == null) {
        print("🛑 Model failed to load after attempt.");
        return 0.0; // or handle error gracefully
      }
    }

    var input = [Float32List.fromList(features)];
    var output = List.filled(1, List.filled(1, 0.0));
    _interpreter!.run(input, output);
    return output[0][0];
  }


  // 👉 Helper: Accepts List<int> and converts to float
  static Future<double> predictFromInt(List<int> features) async {
    return await runMalwarePrediction(
      features.map((e) => e.toDouble()).toList()
    );
  }

  static void dispose() {
    _interpreter?.close();
    _interpreter = null;
  }
}
