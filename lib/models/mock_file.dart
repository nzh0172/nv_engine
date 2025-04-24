// Mock file model for testing purposes
class MockFile {
  final String filename;
  final List<double> features; // entropy, is_packed, api_count, max_entropy
  double? prediction; // 1 = infected, 0 = safe // model's confidence (0.0 to 1.0)

  MockFile({required this.filename, required this.features, this.prediction});

  bool get infected => prediction != null && prediction! > 0.5;

}
