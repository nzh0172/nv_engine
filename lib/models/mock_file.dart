// Mock file model for testing purposes
class MockFile {
  final String filename;
  final List<double> features; // entropy, is_packed, api_count, max_entropy
  int? prediction; // 1 = infected, 0 = safe

  MockFile({required this.filename, required this.features, this.prediction});
}
