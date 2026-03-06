#!/usr/bin/env python3
"""
Synthetic Auditor - Private AI & The "Offline" Analyst
ML Resilience Hackathon Tool

Usage:
    python main.py --input <zip_or_folder> [--context <context_note.txt>] [--output <output_dir>]
    python main.py --input sample_data/  (uses bundled sample data)
"""

import argparse
import os
import sys
import zipfile
import tempfile
import shutil
from pathlib import Path

from parsers.parser_engine import ParserEngine
from llm.ollama_client import OllamaClient
from report.pdf_generator import PDFGenerator
from utils.logger import get_logger

logger = get_logger("main")


def extract_zip(zip_path: str, dest_dir: str) -> str:
    """Extract zip file and return extraction path."""
    logger.info(f"Extracting zip: {zip_path}")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(dest_dir)
    return dest_dir


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic Auditor - AI-powered Security Audit Report Generator (Offline)"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to zip file or folder containing evidence files (XML, JSON, CSV, TXT, LOG)"
    )
    parser.add_argument(
        "--context", "-c",
        default=None,
        help="Path to a context note file describing the organization (optional)"
    )
    parser.add_argument(
        "--output", "-o",
        default="./output",
        help="Output directory for the generated PDF report (default: ./output)"
    )
    parser.add_argument(
        "--model",
        default="mistral",
        help="Ollama model to use (default: mistral)"
    )
    parser.add_argument(
        "--org-name",
        default="Target Organization",
        help="Organization name for the report"
    )
    args = parser.parse_args()

    # --- Resolve input path ---
    input_path = Path(args.input)
    temp_dir = None

    if not input_path.exists():
        logger.error(f"Input path does not exist: {input_path}")
        sys.exit(1)

    if input_path.suffix.lower() == ".zip":
        logger.info(f"📦 Mode: ZIP file  →  {input_path.name}")
        temp_dir = tempfile.mkdtemp(prefix="synthetic_auditor_")
        data_dir = extract_zip(str(input_path), temp_dir)
    elif input_path.is_file():
        logger.info(f"📄 Mode: Single file  →  {input_path.name}")
        data_dir = str(input_path)
    else:
        logger.info(f"📁 Mode: Folder  →  {input_path}")
        data_dir = str(input_path)

    # --- Read context note ---
    context_note = ""
    if args.context and Path(args.context).exists():
        with open(args.context, "r", encoding="utf-8", errors="ignore") as f:
            context_note = f.read()
        logger.info(f"Loaded context note: {args.context}")
    else:
        context_note = f"Organization: {args.org_name}. Security assessment of on-premises and cloud infrastructure."

    # --- Parse all evidence files ---
    logger.info("=" * 60)
    logger.info("PHASE 1: Parsing evidence files...")
    logger.info("=" * 60)
    engine = ParserEngine(data_dir)
    findings = engine.parse_all()
    logger.info(f"Total findings extracted: {len(findings)}")

    if not findings:
        logger.warning("No findings extracted. Check input data.")
        sys.exit(1)

    # --- LLM Analysis ---
    logger.info("=" * 60)
    logger.info("PHASE 2: Running local LLM analysis via Ollama...")
    logger.info("=" * 60)
    ollama = OllamaClient(model=args.model)

    if not ollama.check_connection():
        logger.error("Cannot connect to Ollama. Make sure Ollama is running: `ollama serve`")
        logger.error(f"And that the model is pulled: `ollama pull {args.model}`")
        sys.exit(1)

    analyzed_findings = ollama.analyze_findings(findings, context_note, args.org_name)
    executive_summary = ollama.generate_executive_summary(analyzed_findings, context_note, args.org_name)

    # --- Generate PDF Report ---
    logger.info("=" * 60)
    logger.info("PHASE 3: Generating PDF report...")
    logger.info("=" * 60)
    os.makedirs(args.output, exist_ok=True)
    output_path = Path(args.output) / "audit_report.pdf"

    pdf_gen = PDFGenerator(org_name=args.org_name)
    pdf_gen.generate(
        findings=analyzed_findings,
        executive_summary=executive_summary,
        context_note=context_note,
        output_path=str(output_path)
    )

    logger.info("=" * 60)
    logger.info(f"✅ Report generated: {output_path}")
    logger.info("=" * 60)

    # Cleanup temp dir
    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
