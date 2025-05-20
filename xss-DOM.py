import os
import re
import json
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from urllib.parse import urljoin

class DOMXSSScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Badass DOM XSS Scanner")
        self.root.geometry("600x500")
        self.root.configure(bg="#1a1a1a")
        self.payloads = []
        self.target_url = ""  # Store target URL for resolving relative paths
        self.setup_gui()

    def setup_gui(self):
        # Styling
        label_style = {"bg": "#1a1a1a", "fg": "#00ff00", "font": ("Arial", 12)}
        entry_style = {"bg": "#333333", "fg": "#ffffff", "insertbackground": "#00ff00", "font": ("Arial", 12)}
        button_style = {"bg": "#006600", "fg": "#ffffff", "font": ("Arial", 12, "bold"), "activebackground": "#008800"}

        # URL Input
        tk.Label(self.root, text="Target URL:", **label_style).pack(pady=10)
        self.url_entry = tk.Entry(self.root, width=50, **entry_style)
        self.url_entry.pack(pady=5)

        # Payload File Input
        tk.Label(self.root, text="Custom Payload File (Optional):", **label_style).pack(pady=10)
        self.payload_entry = tk.Entry(self.root, width=50, **entry_style)
        self.payload_entry.pack(pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_payload_file, **button_style).pack(pady=5)

        # Scan Button
        tk.Button(self.root, text="Run Scan", command=self.run_scan, **button_style).pack(pady=10)

        # Output Area
        self.output_text = scrolledtext.ScrolledText(self.root, width=60, height=15, bg="#333333", fg="#00ff00", font=("Arial", 10))
        self.output_text.pack(pady=10)

        # Clear and Save Report Buttons
        tk.Button(self.root, text="Clear Output", command=self.clear_output, **button_style).pack(side=tk.LEFT, padx=10)
        tk.Button(self.root, text="Save Report", command=self.save_report, **button_style).pack(side=tk.RIGHT, padx=10)

    def browse_payload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            self.payload_entry.delete(0, tk.END)
            self.payload_entry.insert(0, file_path)

    def _load_payloads(self, payload_file):
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return ['<script>alert(1)</script>', '" onmouseover=alert(1)', "'><img src=x onerror=alert(1)>", 'javascript:alert(1)']

    def scan_js(self, js_code):
        sources = ['document.location', 'document.referrer', 'window.location', 'window.location.href']
        sinks = ['innerHTML', 'outerHTML', 'document.write', 'eval']
        vulnerabilities = []

        for source in sources:
            for sink in sinks:
                pattern = re.compile(r'({})\s*=\s*({})'.format(source, sink))
                if pattern.search(js_code):
                    vulnerabilities.append({'source': source, 'sink': sink})
        return vulnerabilities

    def analyze_html(self, target_url):
        try:
            response = requests.get(target_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            inline_scripts = soup.find_all('script')

            # Resolve relative URLs to absolute URLs
            js_files = [urljoin(target_url, script['src']) for script in scripts if script.get('src')]
            inline_js = [script.string for script in inline_scripts if script.string]

            return js_files, inline_js
        except requests.RequestException as e:
            self.output_text.insert(tk.END, f"Error fetching URL {target_url}: {e}\n")
            return [], []

    def generate_report(self, vulnerabilities):
        report = {'vulnerabilities': vulnerabilities}
        with open('dom_xss_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        self.output_text.insert(tk.END, "[+] Report generated: dom_xss_report.json\n")

    def run_scan(self):
        self.target_url = self.url_entry.get().strip()
        payload_file = self.payload_entry.get().strip() or None

        if not self.target_url:
            messagebox.showerror("Error", "Please enter a target URL!")
            return

        # Ensure target URL has a scheme
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'https://' + self.target_url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, self.target_url)

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"[*] Scanning {self.target_url}...\n")
        self.payloads = self._load_payloads(payload_file)

        js_files, inline_js = self.analyze_html(self.target_url)
        all_vulnerabilities = []

        for js_file in js_files:
            try:
                self.output_text.insert(tk.END, f"[*] Fetching JS file: {js_file}\n")
                response = requests.get(js_file, timeout=10)
                response.raise_for_status()
                vulnerabilities = self.scan_js(response.text)
                all_vulnerabilities.extend(vulnerabilities)
                self.output_text.insert(tk.END, f"[*] Scanned JS file: {js_file}\n")
                for vuln in vulnerabilities:
                    self.output_text.insert(tk.END, f"[!] Found vulnerability: Source={vuln['source']}, Sink={vuln['sink']}\n")
            except requests.RequestException as e:
                self.output_text.insert(tk.END, f"Error fetching JS file {js_file}: {e}\n")

        for js_code in inline_js:
            vulnerabilities = self.scan_js(js_code)
            all_vulnerabilities.extend(vulnerabilities)
            for vuln in vulnerabilities:
                self.output_text.insert(tk.END, f"[!] Found inline JS vulnerability: Source={vuln['source']}, Sink={vuln['sink']}\n")

        if all_vulnerabilities:
            self.output_text.insert(tk.END, f"[+] Found {len(all_vulnerabilities)} vulnerabilities!\n")
            self.generate_report(all_vulnerabilities)
        else:
            self.output_text.insert(tk.END, "[-] No DOM XSS vulnerabilities found.\n")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

    def save_report(self):
        if os.path.exists('dom_xss_report.json'):
            messagebox.showinfo("Success", "Report saved as dom_xss_report.json")
        else:
            messagebox.showerror("Error", "No report generated yet!")

if __name__ == "__main__":
    root = tk.Tk()
    app = DOMXSSScanner(root)
    root.mainloop()
