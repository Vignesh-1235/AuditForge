from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import tempfile
from pathlib import Path

# Import the existing backend logic
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from parsers.parser_engine import ParserEngine
from llm.ollama_client import OllamaClient
from report.pdf_generator import PDFGenerator
from utils.logger import get_logger
import zipfile

logger = get_logger("api")

app = FastAPI(title="Synthetic Auditor API")

# Setup CORS to allow the React frontend to communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def extract_zip(zip_path: str, dest_dir: str) -> str:
    """Extract zip file and return extraction path."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(dest_dir)
    return dest_dir

@app.post("/analyze")
async def analyze_evidence(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    logger.info(f"Received file upload: {file.filename}")

    # Create temporary directories for processing
    temp_dir = tempfile.mkdtemp(prefix="auditor_api_")
    output_dir = os.path.join(temp_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    
    file_path = os.path.join(temp_dir, file.filename)
    
    try:
        # Save uploaded file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Determine if it's a zip or single evidence file
        if file.filename.lower().endswith('.zip'):
            data_dir = extract_zip(file_path, temp_dir)
        else:
            data_dir = temp_dir # The temp_dir itself holds the single file
            
        # Default context
        context_note = "Organization: Target Organization. Security assessment of on-premises and cloud infrastructure."
        org_name = "Target Organization"
        
        # 1. Parse
        engine = ParserEngine(data_dir)
        findings = engine.parse_all()
        
        if not findings:
            raise HTTPException(status_code=400, detail="No findings extracted from the uploaded files.")
            
        # 2. LLM Analysis
        ollama = OllamaClient(model="mistral")
        if not ollama.check_connection():
            raise HTTPException(status_code=503, detail="Cannot connect to local Ollama. Ensure it's running.")
            
        analyzed_findings = ollama.analyze_findings(findings, context_note, org_name)
        executive_summary = ollama.generate_executive_summary(analyzed_findings, context_note, org_name)
        
        # 3. Generate PDF
        output_pdf_path = os.path.join(output_dir, "audit_report.pdf")
        pdf_gen = PDFGenerator(org_name=org_name)
        pdf_gen.generate(
            findings=analyzed_findings,
            executive_summary=executive_summary,
            context_note=context_note,
            output_path=output_pdf_path
        )
        
        # Return the generated PDF so the user's browser prompts a download
        return FileResponse(
            path=output_pdf_path, 
            filename="audit_report.pdf", 
            media_type="application/pdf",
            # Important: we should keep the temp_dir alive just long enough to send the response.
            # FileResponse handles opening it, but cleanup is tricky in FastAPI without BackgroundTasks.
            # For simplicity in this local tool, we let the OS clean up /tmp eventually or we'd add a background task.
        )
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
