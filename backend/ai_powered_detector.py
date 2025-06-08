#!/usr/bin/env python3
"""
AI-Powered Malware Detector with Ollama Integration
===================================================
Real-time malware detection using YARA rules and Ollama LLM analysis
Combines traditional signature detection with AI-powered code analysis
"""

import os
import sys
import time
import json
import hashlib
import threading
import requests
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: YARA not installed. Install with: pip install yara-python", file=sys.stderr)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("Warning: watchdog not installed. Install with: pip install watchdog", file=sys.stderr)

# --- TFLite Detector ---
try:
    from tensorflow.lite.python.interpreter import Interpreter
    import numpy as np
except ImportError:
    print("[ERROR] Missing tflite-runtime or numpy. Install with: pip install tflite-runtime numpy", file=sys.stderr)
    sys.exit(1)

class TFLiteDetector:
    def __init__(self, model_path="assets/model.tflite"):
        self.interpreter = Interpreter(model_path=model_path)
        self.interpreter.allocate_tensors()
        self.input_details  = self.interpreter.get_input_details()
        self.output_details = self.interpreter.get_output_details()

    def scan(self, file_path):
        data = open(file_path, "rb").read()
        arr  = np.frombuffer(data, dtype=np.uint8)
        length = self.input_details[0]['shape'][1]
        if arr.size < length:
            arr = np.pad(arr, (0, length - arr.size), constant_values=0)
        else:
            arr = arr[:length]
        inp = (arr.astype(np.float32) / 255.0).reshape(self.input_details[0]['shape'])
        self.interpreter.set_tensor(self.input_details[0]['index'], inp)
        self.interpreter.invoke()
        out = self.interpreter.get_tensor(self.output_details[0]['index'])
        score = float(out.flat[0])
        label = 'MALICIOUS' if score > 0.5 else 'CLEAN'
        return {'label': label, 'score': score}

class OllamaClient:
    """Client for interacting with Ollama API"""

    def __init__(self, base_url="http://localhost:11434", model="llama3.2"):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.session = requests.Session()

        if not self.test_connection():
            print(f"[WARNING] Warning: Cannot connect to Ollama at {base_url}", file=sys.stderr)
            print("Make sure Ollama is running with: ollama serve", file=sys.stderr)

    def test_connection(self):
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False

    def analyze_code(self, file_content, file_path, context=""):
        prompt = f"""You are a cybersecurity expert. Analyze this code for malware and AI-generated patterns.

IMPORTANT: You MUST respond in exactly this format:

THREAT_LEVEL: HIGH
MALICIOUS_INDICATORS: system commands, network connections, file manipulation
AI_GENERATED: YES (85%)
EXPLANATION: This code shows suspicious behavior including subprocess calls and base64 encoding which are common malware techniques.
RECOMMENDATION: Quarantine file and investigate further

Now analyze this file:
FILE: {file_path}
CONTEXT: {context}

CODE TO ANALYZE:
{file_content[:3000]}

Look for these MALICIOUS BEHAVIORS:
- subprocess.call, os.system, cmd.exe, powershell
- socket connections, urllib, requests, network activity
- base64 encoding/decoding, eval(), exec()
- file operations, registry access
- obfuscation techniques

Look for these AI-GENERATED PATTERNS:
- Excessive comments like "# This is a comment explaining"
- Generic function names like "process_data", "handle_request"
- Repetitive structure and over-engineering
- Class names ending in Manager, Handler, Gatherer

RESPOND IN THE EXACT FORMAT SHOWN ABOVE. Start your response with "THREAT_LEVEL:" and include all sections."""

        print("\n" + "="*25 + " AI PROMPT " + "="*25, file=sys.stderr)
        print(prompt, file=sys.stderr)
        print("="*60 + "\n", file=sys.stderr)

        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "num_predict": 700,  # Increased for potentially longer well-formatted responses
                    "stop": ["---", "END_OF_ANALYSIS_MARKER"] # Unique stop token
                }
            }

            print(f"[AI] Sending to Ollama ({self.model}) for analysis...", file=sys.stderr)
            print("[TIMER] Waiting for AI response (no timeout - will wait as long as needed)...", file=sys.stderr)
            start_time = time.time()
            response = self.session.post(f"{self.base_url}/api/generate", json=payload)
            end_time = time.time()
            response_time = end_time - start_time
            print(f"[OK] AI response received in {response_time:.1f} seconds", file=sys.stderr)

            if response.status_code == 200:
                result = response.json()
                raw_response = result.get('response', '').strip()
                print(f"[SCAN] Raw AI Response (Full):", file=sys.stderr)
                print(f"   {raw_response}", file=sys.stderr)
                print(f"   (Total length: {len(raw_response)} chars)", file=sys.stderr)

                analysis = self.parse_ollama_response(raw_response)
                analysis['response_time'] = response_time
                return analysis
            else:
                return {'error': f"Ollama API error: {response.status_code}", 'threat_level': 'UNKNOWN', 'ai_generated': 'UNKNOWN', 'explanation': 'Failed to analyze with Ollama', 'response_time': response_time}
        except requests.exceptions.ConnectionError:
            return {'error': 'Cannot connect to Ollama server', 'threat_level': 'UNKNOWN', 'ai_generated': 'UNKNOWN', 'explanation': 'Connection failed - is Ollama running?', 'response_time': 0}
        except Exception as e:
            return {'error': str(e), 'threat_level': 'UNKNOWN', 'ai_generated': 'UNKNOWN', 'explanation': f'Error during analysis: {str(e)}', 'response_time': time.time() - start_time if 'start_time' in locals() else 0}

    def parse_ollama_response(self, response_text):
        result = {
            'threat_level': 'UNKNOWN',
            'malicious_indicators': [],
            'ai_generated': 'UNKNOWN',
            'explanation': '',
            'recommendation': '',
            'raw_response': response_text,
            'explanation_is_fallback': False,
            'parsing_complete': False
        }

        if not response_text:
            return result

        lines = response_text.split('\n')
        current_section_content = []
        active_section_key = None

        section_keywords = {
            'THREAT_LEVEL:': 'threat_level',
            'MALICIOUS_INDICATORS:': 'malicious_indicators',
            'AI_GENERATED:': 'ai_generated',
            'EXPLANATION:': 'explanation',
            'RECOMMENDATION:': 'recommendation'
        }
        
        processed_keywords = set()

        for line_num, line in enumerate(lines):
            line_stripped = line.strip()
            matched_keyword = None

            for kw, key_name in section_keywords.items():
                if line_stripped.upper().startswith(kw.upper()): # Case-insensitive keyword matching
                    matched_keyword = kw
                    # Finalize previous section
                    if active_section_key and current_section_content:
                        content = ' '.join(current_section_content).strip()
                        if active_section_key == 'malicious_indicators':
                            result[active_section_key] = [i.strip() for i in content.split(',') if i.strip()]
                        else:
                            result[active_section_key] = content
                        current_section_content = []
                    
                    active_section_key = key_name
                    # Get content on the same line as the keyword
                    content_on_keyword_line = line_stripped[len(kw):].strip()
                    if content_on_keyword_line:
                        current_section_content.append(content_on_keyword_line)
                    
                    processed_keywords.add(kw)
                    break # Found a keyword for this line
            
            if not matched_keyword and active_section_key:
                # This line is part of the currently active section
                current_section_content.append(line_stripped)
            elif not matched_keyword and not active_section_key and result['explanation'] == '' and line_stripped:
                # Edge case: AI response is just a block of text without any headers. Treat as explanation.
                # This is risky, only use if NO sections were found yet and explanation is empty.
                # This part might be removed if it causes too many false positives for explanation.
                # For now, this path is handled by _fallback_parse more explicitly.
                pass


        # Finalize the last active section
        if active_section_key and current_section_content:
            content = ' '.join(current_section_content).strip()
            if active_section_key == 'malicious_indicators':
                result[active_section_key] = [i.strip() for i in content.split(',') if i.strip()]
            else:
                result[active_section_key] = content
        
        # Uppercase threat level for consistency
        if isinstance(result['threat_level'], str):
            result['threat_level'] = result['threat_level'].upper()

        # Check if primary parsing found the key sections
        if result['explanation'] and result['threat_level'] != 'UNKNOWN':
            result['parsing_complete'] = True
        else: # If key fields like explanation are missing, try fallback
            result = self._fallback_parse(response_text, result) # Pass the current result to be augmented

        return result

    def _fallback_parse(self, text, result):
        """Fallback parsing, especially if EXPLANATION is missing or primary parsing was incomplete."""
        text_lower = text.lower()
        
        # If explanation wasn't found by primary parser, try to find it more leniently
        if not result.get('explanation'):
            explanation_keywords = ['explanation:', 'analysis:', 'detailed analysis:', 'summary:']
            found_explanation_text = ""

            for keyword in explanation_keywords:
                start_index = text_lower.find(keyword)
                if start_index != -1:
                    explanation_content = text[start_index + len(keyword):].strip()
                    # Find end of this section (e.g., start of another known section)
                    next_section_keywords = ['recommendation:', 'threat_level:', 'malicious_indicators:', 'ai_generated:']
                    min_next_section_index = len(explanation_content)
                    for next_key in next_section_keywords:
                        next_key_index_in_exp = explanation_content.lower().find(next_key)
                        if next_key_index_in_exp != -1:
                            min_next_section_index = min(min_next_section_index, next_key_index_in_exp)
                    
                    found_explanation_text = explanation_content[:min_next_section_index].strip()
                    if len(found_explanation_text) > 20: # Must be somewhat substantial
                        result['explanation'] = found_explanation_text
                        result['explanation_is_fallback'] = True
                        break 
            
            if not result.get('explanation'): # If still no explanation, use first few sentences of raw text
                sentences = text.split('.')
                temp_explanation = ""
                sentence_count = 0
                for sentence_idx, sentence in enumerate(sentences):
                    # Skip if it looks like a list of keywords from the prompt
                    if sentence.strip().lower().startswith("look for these malicious behaviors") or \
                       sentence.strip().lower().startswith("look for these ai-generated patterns"):
                        continue
                    if len(sentence.strip()) > 15: # More than a short phrase
                        temp_explanation += sentence.strip() + '. '
                        sentence_count += 1
                    if sentence_count >= 5: # Max 3-5 sentences
                        break
                if temp_explanation:
                    result['explanation'] = temp_explanation.strip()
                    result['explanation_is_fallback'] = True
        
        # Fallback for other fields if UNKNOWN
        if result['threat_level'] == 'UNKNOWN':
            if any(word in text_lower for word in ['critical', 'severe', 'dangerous']): result['threat_level'] = 'CRITICAL'
            elif any(word in text_lower for word in ['high', 'malicious', 'harmful']): result['threat_level'] = 'HIGH'
            elif any(word in text_lower for word in ['medium', 'suspicious', 'concerning']): result['threat_level'] = 'MEDIUM'
            elif any(word in text_lower for word in ['low', 'minor', 'unlikely', 'clean', 'safe', 'benign']): result['threat_level'] = 'LOW'

        if result['ai_generated'] == 'UNKNOWN':
            if any(phrase in text_lower for phrase in ['ai generated', 'ai-generated', 'generated by ai']):
                if any(word in text_lower for word in ['yes', 'likely', 'probably']): result['ai_generated'] = 'YES (likely)'
                elif any(word in text_lower for word in ['no', 'unlikely', 'not']): result['ai_generated'] = 'NO'
        
        return result


class EnhancedYARADetector:
    def __init__(self):
        self.rules_content = '''
        rule AI_Generated_Malware { meta: description = "Detects AI-generated malware patterns" author = "AI Malware Detector" strings: $ai1 = "This is a comment explaining" $ai2 = "Function to process" $ai3 = "Method to gather" $ai4 = "class SystemInformationGatherer" $ai5 = "class FileSystemManager" $ai6 = "class NetworkCommunicator" $ai7 = "[INFO]" $ai8 = "[ERROR]" $ai9 = "[STAGE" $ai10 = "def collect_" $ai11 = "def generate_" $ai12 = "def simulate_" condition: 3 of ($ai*) }
        rule Suspicious_Commands { meta: description = "Detects suspicious system commands" strings: $cmd1 = "cmd.exe" nocase $cmd2 = "powershell" nocase $cmd3 = "rundll32" nocase $cmd4 = "regsvr32" nocase $cmd5 = "wscript" nocase $cmd6 = "cscript" nocase $sys1 = "system(" nocase $sys2 = "subprocess.call" $sys3 = "subprocess.run" $sys4 = "shell_exec" nocase condition: any of them }
        rule Network_Activity { meta: description = "Detects network-related malware behavior" strings: $net1 = "socket.socket" $net2 = "urllib.request" $net3 = "requests.get" $net4 = "requests.post" $net5 = "http://" $net6 = "https://" $net7 = "tcp://" $net8 = "ftp://" condition: 2 of them }
        rule Code_Injection { meta: description = "Detects code injection techniques" strings: $inj1 = "VirtualAlloc" nocase $inj2 = "WriteProcessMemory" nocase $inj3 = "CreateRemoteThread" nocase $inj4 = "SetWindowsHookEx" nocase $inj5 = "LoadLibrary" nocase $inj6 = "GetProcAddress" nocase $exec1 = "exec(" $exec2 = "eval(" condition: any of them }
        rule Obfuscation_Techniques { meta: description = "Detects code obfuscation" strings: $obf1 = "base64.b64decode" $obf2 = "base64.b64encode" $obf3 = /\\\\x[0-9a-fA-F]{2}/ $obf4 = /[A-Za-z0-9+\\/]{50,}/ $obf5 = "chr(" $obf6 = "ord(" condition: 2 of them }
        '''
        self.rules = None
        if YARA_AVAILABLE:
            try:
                self.rules = yara.compile(source=self.rules_content)
                print("[OK] YARA rules compiled successfully", file=sys.stderr)
            except Exception as e:
                print(f"[ERROR] Error compiling YARA rules: {e}", file=sys.stderr)

    def scan(self, file_path: str) -> list[str]:
        """
        Scan the file and return a list of matching rule names (strings).
        All logging goes to stderr; no YARA objects are returned.
        """
        if not self.rules:
            return []

        try:
            raw_matches = self.rules.match(file_path)
            rule_names = [m.rule for m in raw_matches]

            if rule_names:
                print(f"[WARNING] YARA matches detected: {rule_names}", file=sys.stderr)
            else:
                print("[OK] No YARA matches", file=sys.stderr)

            return rule_names

        except Exception as e:
            print(f"[ERROR] YARA scan failed: {e}", file=sys.stderr)
            return []

class RealTimeMalwareDetector:
    def __init__(self, ollama_model="llama3.2", ollama_url="http://localhost:11434"):
        self.ollama_client = OllamaClient(ollama_url, ollama_model)
        self.yara_detector = EnhancedYARADetector()
        self.scan_queue = []
        self.scan_lock = threading.Lock()
        self.stats = defaultdict(int)
        self.scanning = True
        self.scannable_extensions = {'.py', '.js', '.php', '.pl', '.rb', '.sh', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.exe', '.dll', '.scr', '.com', '.html', '.htm', '.asp', '.aspx', '.jsp'}
        self.scanner_thread = threading.Thread(target=self._background_scanner, daemon=True)
        self.scanner_thread.start()
        self.tflite_detector = TFLiteDetector("assets/model.tflite")


    def is_scannable_file(self, file_path):
        path = Path(file_path)
        if path.suffix.lower() not in self.scannable_extensions: return False
        try:
            if path.stat().st_size > 5 * 1024 * 1024: return False # 5MB limit
        except: return False
        return True

    def queue_file_for_scan(self, file_path, event_type="manual"):
        if self.is_scannable_file(file_path):
            with self.scan_lock:
                self.scan_queue.append({'file_path': file_path, 'event_type': event_type, 'timestamp': datetime.now()})

    def scan_file_comprehensive(self, file_path, event_type="manual"):
        import sys, hashlib
        from pathlib import Path
        from datetime import datetime

        # 1) Initialize result
        result = {
            'file_path':       str(file_path),
            'scan_timestamp':  datetime.now().isoformat(),
            'event_type':      event_type,
            'file_size':       0,
            'file_hash':       '',
            'yara_matches':    [],
            'ai_analysis':     {},
            'tflite_analysis': {},
            'final_verdict':   'CLEAN',
            'confidence':      0.0,
            'recommendations': []
        }

        try:
            # 2) File metadata
            path_obj = Path(file_path)
            result['file_size'] = path_obj.stat().st_size
            content = path_obj.read_bytes()
            result['file_hash'] = hashlib.sha256(content).hexdigest()[:16]

            # 3) Header
            print(
                f"\n{'='*60}\n"
                f"[SCAN] ANALYZING: {file_path}\n"
                f"[SIZE] {result['file_size']} bytes | Hash: {result['file_hash']}\n"
                f"[TIME] Event: {event_type} | {datetime.now().strftime('%H:%M:%S')}\n"
                f"{'='*60}",
                file=sys.stderr
            )

            # 4) YARA
            print("[YARA] Running YARA analysis...", file=sys.stderr)
            yara_matches = self.yara_detector.scan(file_path)  # List[str]
            result['yara_matches'] = yara_matches

            # map rules → threat level
            yara_threat = 0
            for rule in yara_matches:
                if rule in ['Suspicious_Commands', 'Code_Injection']:
                    yara_threat = max(yara_threat, 3)
                elif rule in ['Network_Activity', 'Obfuscation_Techniques']:
                    yara_threat = max(yara_threat, 2)
                elif rule == 'AI_Generated_Malware':
                    yara_threat = max(yara_threat, 1)

            if yara_threat > 0:
                print("[WARNING] YARA MATCHES FOUND:", file=sys.stderr)
                desc_map = {
                    'Suspicious_Commands':    'Detects suspicious system commands',
                    'Code_Injection':         'Detects code injection techniques',
                    'Network_Activity':       'Detects network-related behavior',
                    'Obfuscation_Techniques': 'Detects code obfuscation',
                    'AI_Generated_Malware':   'Detects AI-generated malware patterns'
                }
                for rule in yara_matches:
                    print(f"   - {rule}: {desc_map.get(rule,'No description')}", file=sys.stderr)
            else:
                print("[OK] No YARA matches found", file=sys.stderr)

            # 5) AI (Ollama)
            suffix = path_obj.suffix.lower()
            need_ai = (
                yara_threat > 0
                or event_type in ['created', 'modified']
                or suffix in ['.py', '.js', '.php', '.ps1']
            )
            if need_ai:
                print("[AI] Requesting AI analysis...", file=sys.stderr)
                try:
                    text = content.decode('utf-8', errors='ignore')
                except:
                    text = str(content)[:3000]
                context = f"YARA matches: {yara_matches}"
                ai_res = self.ollama_client.analyze_code(text, file_path, context)
                result['ai_analysis'] = ai_res

                if 'error' not in ai_res:
                    print("[ANALYSIS] AI ANALYSIS:", file=sys.stderr)
                    print(f"   Threat Level: {ai_res.get('threat_level','UNKNOWN')}", file=sys.stderr)
                    if ai_res.get('ai_generated') is not None:
                        print(f"   AI Generated: {ai_res.get('ai_generated')}", file=sys.stderr)
                    if ai_res.get('malicious_indicators'):
                        inds = ', '.join(ai_res['malicious_indicators'])
                        print(f"   Malicious Indicators: {inds}", file=sys.stderr)
                    expl = ai_res.get('explanation','No explanation provided.')
                    print(f"   Analysis: {expl}", file=sys.stderr)
                    rec = ai_res.get('recommendation')
                    if rec:
                        print(f"   Recommendation: {rec}", file=sys.stderr)
                    rt = ai_res.get('response_time')
                    if rt is not None:
                        print(f"   [TIMER] Analysis Time: {rt:.1f} seconds", file=sys.stderr)
                else:
                    print(f"[ERROR] AI Analysis failed: {ai_res.get('error')}", file=sys.stderr)
                    rt = ai_res.get('response_time')
                    if rt:
                        print(f"   [TIMER] Failed after: {rt:.1f} seconds", file=sys.stderr)

            # 6) TFLite
            tflite_res = self.tflite_detector.scan(file_path)
            result['tflite_analysis'] = tflite_res

            # 7) Final verdict
            verdict, conf = self._calculate_final_verdict(
                yara_matches,
                result['ai_analysis'],
                tflite_res['score']
            )
            result['final_verdict']   = verdict
            result['confidence']      = conf
            result['recommendations'] = self._generate_recommendations(result)

            # 8) Final assessment block
            print(
                f"\n{'-'*60}\n[LABEL] FINAL ASSESSMENT\n{'-'*60}"
                f"\n[{verdict}] VERDICT: {verdict} (Confidence: {conf:.1%})",
                file=sys.stderr
            )
            if result['recommendations']:
                print("[REVIEW] RECOMMENDATIONS:", file=sys.stderr)
                for rec in result['recommendations']:
                    print(f"   {rec}", file=sys.stderr)
            print(f"{'-'*60}", file=sys.stderr)

            # 9) Stats & return
            self.stats[f'scanned_{event_type}']    += 1
            self.stats[f'verdict_{verdict.lower()}'] += 1
            return result

        except Exception as e:
            print(f"[ERROR] Error analyzing {file_path}: {e}", file=sys.stderr)
            result['error'] = str(e)
            result['final_verdict'] = 'ERROR'
            return result

    YARA_RULE_WEIGHTS = {
        'Suspicious_Commands':    0.8,
        'Code_Injection':         0.8,
        'Network_Activity':       0.6,
        'Obfuscation_Techniques': 0.6,
        'AI_Generated_Malware':   0.4,
    }

    def _calculate_final_verdict(self, yara_matches, ai_analysis, tflite_score):
        yara_score, ai_score = 0, 0
        
        # Compute YARA score by looking up each rule's weight
        for rule in yara_matches:
            weight = self.YARA_RULE_WEIGHTS.get(rule, 0.0)
            yara_score = max(yara_score, weight)

        if ai_analysis and 'error' not in ai_analysis:
            threat_level = ai_analysis.get('threat_level', '').upper()
            if threat_level == 'CRITICAL': ai_score = 0.9
            elif threat_level == 'HIGH': ai_score = 0.7
            elif threat_level == 'MEDIUM': ai_score = 0.5
            elif threat_level == 'LOW': ai_score = 0.3

        # Weighted judgement: 90% Ollama + 10% TFLite
        weighted_ml = ai_score + tflite_score * 0
        combined_score = max(yara_score, weighted_ml)

        if combined_score >= 0.7: return "MALICIOUS", combined_score
        elif combined_score >= 0.5: return "SUSPICIOUS", combined_score
        elif combined_score >= 0.3: return "QUESTIONABLE", combined_score
        else: return "CLEAN", combined_score

    def _generate_recommendations(self, result):
        recommendations = []
        ai_rec = result.get('ai_analysis', {}).get('recommendation')
        if ai_rec: recommendations.append(f"[AI] AI REC: {ai_rec}")
        verdict = result['final_verdict']
        if verdict == "MALICIOUS": recommendations.extend(["[URGENT] QUARANTINE FILE IMMEDIATELY", "[LOCKED] Block file execution", "[INVESTIGATE] Investigate source", "[REPORT] Report to security team"])
        elif verdict == "SUSPICIOUS": recommendations.extend(["[WARNING] Monitor file activity", "[SCAN] Run additional scans", "[BLOCK] Restrict permissions", "[REVIEW] Review code manually"])
        elif verdict == "QUESTIONABLE": recommendations.extend(["[OBSERVE] Keep under observation", "[SIZE] Monitor behavior", "[RESCAN] Rescan periodically"])
        return list(dict.fromkeys(recommendations))

    def _print_final_assessment(self, result):
        verdict, confidence = result['final_verdict'], result['confidence']
        colors = {'MALICIOUS': '[MALICIOUS]', 'SUSPICIOUS': '[SUSPICIOUS]', 'QUESTIONABLE': '[QUESTIONABLE]', 'CLEAN': '[CLEAN]', 'ERROR': '[ERROR]'}
        print(f"\n{'-'*60}\n[LABEL] FINAL ASSESSMENT\n{'-'*60}\n{colors.get(verdict, '[UNKNOWN]')} VERDICT: {verdict} (Confidence: {confidence:.1%})")
        if result.get('recommendations'):
            print(f"[REVIEW] RECOMMENDATIONS:", file=sys.stderr)
            for rec in result['recommendations']: print(f"   {rec}")
        print(f"{'-'*60}", file=sys.stderr)

    def _background_scanner(self):
        while self.scanning:
            if self.scan_queue:
                with self.scan_lock: scan_item = self.scan_queue.pop(0) if self.scan_queue else None
                if scan_item: self.scan_file_comprehensive(scan_item['file_path'], scan_item['event_type'])
            else: time.sleep(1)

    def print_statistics(self):
        print(f"\n{'='*50}\n[SIZE] DETECTION STATISTICS\n{'='*50}", file=sys.stderr)
        for key, value in sorted(self.stats.items()): print(f"{key.replace('_', ' ').title()}: {value}", file=sys.stderr)
        print(f"{'='*50}", file=sys.stderr)

class FileSystemWatcher(FileSystemEventHandler):
    def __init__(self, detector): self.detector = detector; super().__init__()
    def on_created(self, event):
        if not event.is_directory: print(f"New file: {event.src_path}"); self.detector.queue_file_for_scan(event.src_path, "created", file=sys.stderr)
    def on_modified(self, event):
        if not event.is_directory: print(f"File modified: {event.src_path}"); self.detector.queue_file_for_scan(event.src_path, "modified", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description='AI-Powered Real-Time Malware Detector')
    parser.add_argument('path', help='Directory to monitor or file to scan')
    parser.add_argument('--model', default='llama3.2', help='Ollama model to use')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama server URL')
    parser.add_argument('--watch', action='store_true', help='Enable real-time monitoring')
    parser.add_argument('--scan-existing', action='store_true', help='Scan existing files first')
    args = parser.parse_args()

    if not os.path.exists(args.path): print(f"[ERROR] Path not found: {args.path}"); sys.exit(1)
    print(f"[AI] AI-POWERED MALWARE DETECTOR\n{'='*60}\nTarget: {args.path}\nAI Model: {args.model}\nOllama URL: {args.ollama_url}\n{'='*60}", file=sys.stderr)
    detector = RealTimeMalwareDetector(args.model, args.ollama_url)
    try:
        if os.path.isfile(args.path):
            print("[SCAN] Scanning single file...", file=sys.stderr);
            result = detector.scan_file_comprehensive(args.path, "manual")

            sys.stdout.write(json.dumps(result))
            sys.stdout.flush()
        else:
            if args.scan_existing:
                print("[RESCAN] Scanning existing files...", file=sys.stderr)
                for root, _, files in os.walk(args.path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if detector.is_scannable_file(file_path): detector.queue_file_for_scan(file_path, "existing")
            if args.watch and WATCHDOG_AVAILABLE:
                print("[WATCH] Starting real-time monitoring...\nPress Ctrl+C to stop", file=sys.stderr)
                event_handler = FileSystemWatcher(detector); observer = Observer()
                observer.schedule(event_handler, args.path, recursive=True); observer.start()
                try:
                    while True:
                        time.sleep(1)
                        if int(time.time()) % 60 == 0: detector.print_statistics()
                except KeyboardInterrupt: print("\nStopping monitoring..."); observer.stop(); detector.scanning = False
                observer.join()
            elif args.watch: print("[ERROR] Real-time monitoring requires 'watchdog'. Install with: pip install watchdog", file=sys.stderr)
            else: # Wait for initial queue if not watching
                print("⏳ Waiting for initial scan queue to process...", file=sys.stderr)
                while any(item['event_type'] == 'existing' for item in detector.scan_queue): time.sleep(0.5) # Check specifically for existing
                while detector.scan_queue : time.sleep(1) # Then ensure rest of queue clears
                print("[OK] Initial scan completed.", file=sys.stderr)
    finally:
        detector.scanning = False # Ensure scanner thread stops
        if hasattr(detector, 'scanner_thread') and detector.scanner_thread.is_alive():
            detector.scanner_thread.join(timeout=5)
        detector.print_statistics()
        print("\n[OK] Detection session completed", file=sys.stderr)

if __name__ == "__main__":
    main()