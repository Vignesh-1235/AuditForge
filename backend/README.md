# 🔍 Synthetic Auditor — Private AI Security Report Generator

> **100% Offline** · Powered by Ollama + Mistral · No data leaves your machine

---

## 📋 What It Does

Synthetic Auditor parses security evidence files (TXT, LOG, CSV, JSON, XML) and uses a **local LLM (Mistral via Ollama)** to:

1. **Extract** High/Critical findings from all evidence files
2. **Analyze** each finding with AI — explaining WHY it's dangerous for the specific org
3. **Generate** a professional PDF audit report with:
   - Executive Summary
   - Technical Scoring Table
   - Detailed Findings with AI analysis + recommendations

---

## ⚙️ Setup

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Install & Start Ollama
```bash
# Install Ollama from https://ollama.com
# Then pull Mistral:
ollama pull mistral

# Start Ollama (keep this running):
ollama serve
```

### 3. Run the tool
```bash
# Using the sample data folder:
python main.py --input sample_data/ --context context_note.txt --org-name "YourClient"

# Using a zip file:
python main.py --input evidence.zip --context context_note.txt --org-name "YourClient"

# With custom output directory:
python main.py --input sample_data/ --output ./reports/ --org-name "AxiomL Client"
```

---

## 📁 Input File Types Supported

| Type | Examples |
|------|---------|
| `.txt` | Nmap output, banners, FTP tests, WAF tests |
| `.log` | Port scan logs, custom test logs, WPScan |
| `.csv` | Host inventory, service lists, notes (MSF exports) |
| `.json` | Structured scan results |
| `.xml` | Nmap XML output |

The tool **recursively walks** any folder structure (including nested zip extraction).

---

## 📊 Output

A professional PDF report is saved to `./output/audit_report.pdf` containing:

- **Cover Page** with severity summary dashboard
- **Executive Summary** (AI-generated, business language)
- **Technical Scoring Table** (all findings sorted by severity)
- **Detailed Findings** (per finding: description, AI analysis, evidence, remediation)
- **Methodology Appendix**

---

## 🗂️ Project Structure

```
synthetic_auditor/
├── main.py                  # Entry point
├── requirements.txt         # Python dependencies
├── context_note.txt         # Organization context (edit this!)
├── parsers/
│   └── parser_engine.py     # Multi-format file parser
├── llm/
│   └── ollama_client.py     # Ollama/Mistral integration
├── report/
│   └── pdf_generator.py     # ReportLab PDF builder
├── utils/
│   └── logger.py            # Logging
└── sample_data/             # Sample evidence files
    ├── evidence/            # From zip
    ├── azure_hosts.csv
    ├── azure_services.csv
    ├── azure_notes.csv
    ├── on-prem_hosts.csv
    ├── on-prem_services.csv
    └── on-prem_notes.csv
```

---

## 🚀 Quick Demo

```bash
# Full run with sample data
python main.py \
  --input sample_data/ \
  --context context_note.txt \
  --org-name "AxiomL Client (PTE Sep 2025)" \
  --output ./output/
```

---

## ⚠️ Constraints

- ✅ **Strictly offline** — no calls to OpenAI, Anthropic, or Google
- ✅ **No hallucination** — AI only analyzes evidence that was parsed
- ✅ **Local CPU/GPU** — runs on your laptop via Ollama

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `Cannot connect to Ollama` | Run `ollama serve` in a terminal |
| `Model not found` | Run `ollama pull mistral` |
| `reportlab not found` | Run `pip install reportlab` |
| Empty findings | Check that input path contains evidence files |
