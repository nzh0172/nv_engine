import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/services.dart' show rootBundle;

class Preprocessor {
  late List<double> mean;
  late List<double> scale;
  late List<List<double>> components;

  Future<void> loadScalerAndPCA() async {
    final scalerJson = await rootBundle.loadString('assets/scaler.json');
    final pcaJson = await rootBundle.loadString('assets/pca.json');

    final scalerData = json.decode(scalerJson);
    final pcaData = json.decode(pcaJson);

    mean = List<double>.from(scalerData['mean']);
    scale = List<double>.from(scalerData['scale']);
    components = List<List<double>>.from(
      pcaData['components'].map<List<double>>((row) => List<double>.from(row)),
    );
  }

  List<double> scaleFeatures(List<double> raw) {
    List<double> scaled = [];
    for (int i = 0; i < raw.length; i++) {
      final value = (raw[i] - mean[i]) / scale[i];
      scaled.add(value);
    }
    return scaled;
  }

  List<double> applyPCA(List<double> scaled) {
    List<double> reduced = [];
    for (var row in components) {
      double dot = 0;
      for (int i = 0; i < scaled.length; i++) {
        dot += scaled[i] * row[i];
      }
      reduced.add(dot);
    }
    return reduced;
  }

  Future<List<double>> transform(List<double> rawFeatures) async {
    await loadScalerAndPCA();
    final scaled = scaleFeatures(rawFeatures);
    return applyPCA(scaled);
  }
}
