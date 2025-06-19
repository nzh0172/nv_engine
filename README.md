# NV Engine
AI-based antivirus with AI-generated malware detection using Tensorflow, Ollama and Flutter.
This antivirus will run locally on your device with no internet dependency.
After scanning a file, it will give a user-friendly AI verdict for malware analysis.

## Prerequisite
Install [Ollama](https://ollama.com/library/llama3.2) (use llama3.2 for faster inference)

## Features
- Scan individual file with scan report
- Real-time detection with watcher on selected directory (default: Downloads)
- Quarantine system with file actions (restore and permanent delete)
- Runs in the background (can be closed on system tray)
- Light/dark mode
- Local antivirus with no network connection

## Model training on Colab
To see how our model is trained, refer to our [Colab Notebook](https://colab.research.google.com/drive/1VmWOxTXLxhftlKCNX_EEfYXCLUE8kaX2?usp=sharing).
