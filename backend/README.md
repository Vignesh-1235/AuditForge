🔍 AuditForge — Private AI Security Report Generator

100% Offline · Powered by Ollama + Mistral · No data leaves your machine

📋 What It Does

AuditForge parses security evidence files (TXT, LOG, CSV, JSON, XML) and uses a local LLM (Mistral via Ollama) to:

Extract High/Critical findings from all evidence files

Analyze each finding with AI — explaining why it's dangerous for the specific organization

Generate a professional PDF audit report with:

Executive Summary

Technical Scoring Table

Detailed Findings with AI analysis and recommendations

AuditForge transforms raw security scan outputs into clear, structured, and actionable security audit reports while keeping all sensitive data completely offline.

⚙️ Setup
1. Install Python dependencies
pip install -r requirements.txt
2. Install & Start Ollama
# Install Ollama from https://ollama.com

# Pull the Mistral model
ollama pull mistral

# Start Ollama (keep this running)
ollama serve
3. Run the Tool

Using the sample data folder

python main.py --input sample_data/ --context context_note.txt --org-name "YourClient"

Using a ZIP file

python main.py --input evidence.zip --context context_note.txt --org-name "YourClient"

Custom output directory

python main.py --input sample_data/ --output ./reports/ --org-name "AxiomL Client"
📁 Input File Types Supported
Type	Examples
.txt	Nmap output, banners, FTP tests, WAF tests
.log	Port scan logs, custom test logs, WPScan
.csv	Host inventory, service lists, notes (MSF exports)
.json	Structured scan results
.xml	Nmap XML output

AuditForge recursively scans any folder structure, including extracted ZIP files.

📊 Output

A professional PDF report is generated at:

./output/audit_report.pdf

The report includes:

Cover Page with severity summary dashboard

Executive Summary (AI-generated in business language)

Technical Scoring Table (all findings sorted by severity)

Detailed Findings with:

vulnerability description

AI risk analysis

evidence references

remediation recommendations

Methodology Appendix

🗂️ Project Structure
auditforge/
├── main.py                  # Entry point
├── requirements.txt         # Python dependencies
├── context_note.txt         # Organization context (edit this)
├── parsers/
│   └── parser_engine.py     # Multi-format file parser
├── llm/
│   └── ollama_client.py     # Ollama/Mistral integration
├── report/
│   └── pdf_generator.py     # ReportLab PDF builder
├── utils/
│   └── logger.py            # Logging utilities
└── sample_data/             # Sample evidence files
    ├── evidence/
    ├── azure_hosts.csv
    ├── azure_services.csv
    ├── azure_notes.csv
    ├── on-prem_hosts.csv
    ├── on-prem_services.csv
    └── on-prem_notes.csv
🚀 Quick Demo
python main.py \
  --input sample_data/ \
  --context context_note.txt \
  --org-name "AxiomL Client (PTE Sep 2025)" \
  --output ./output/
⚠️ Constraints

✅ Strictly offline — no OpenAI, Anthropic, or Google APIs

✅ Evidence-based analysis — AI only analyzes parsed data

✅ Local execution — runs fully on CPU/GPU via Ollama

🛠️ Troubleshooting
Problem	                  Solution
Cannot connect to Ollama	Run ollama serve
Model not found	         Run ollama pull mistral
reportlab missing	         Run pip install reportlab
No findings detected	      Verify that input path contains evidence files
