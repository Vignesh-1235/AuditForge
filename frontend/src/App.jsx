import { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import { ShieldCheck, UploadCloud, FileType, CheckCircle, Download } from 'lucide-react';
import { compressFilesToZip } from './utils/zip';
import { saveAs } from 'file-saver';
import './App.css';

const API_URL = 'http://localhost:8000/analyze';

function App() {
  const [initialLoad, setInitialLoad] = useState(true);
  const [status, setStatus] = useState('idle'); // idle, processing, done, error
  const [errorMessage, setErrorMessage] = useState('');
  const [pdfBlob, setPdfBlob] = useState(null);
  const [progress, setProgress] = useState(0);

  // Fake initial professional small time loading page
  useEffect(() => {
    const timer = setTimeout(() => {
      setInitialLoad(false);
    }, 1500); // 1.5 second initial load
    return () => clearTimeout(timer);
  }, []);

  const onDrop = useCallback(async (acceptedFiles) => {
    if (!acceptedFiles || acceptedFiles.length === 0) return;

    setStatus('processing');
    setErrorMessage('');

    try {
      let fileToUpload;
      const isSingleZip = acceptedFiles.length === 1 && acceptedFiles[0].name.toLowerCase().endsWith('.zip');

      if (isSingleZip) {
        fileToUpload = acceptedFiles[0];
      } else {
        // We have multiple files or unzipped folder dropped. Compress them client-side.
        const zipBlob = await compressFilesToZip(acceptedFiles);
        // Create a File object from the Blob
        fileToUpload = new File([zipBlob], 'evidence.zip', { type: 'application/zip' });
      }

      const formData = new FormData();
      formData.append('file', fileToUpload);

      // Simulate the AI parsing time (30% to 80%) smoothly
      let currentProgress = 30;
      const interval = setInterval(() => {
        if (currentProgress < 80) {
          currentProgress += 1;
          setProgress(Math.floor(currentProgress));
        } else {
          clearInterval(interval);
        }
      }, 500); // Progresses 1% every 0.5s while waiting for backend response

      const response = await axios.post(API_URL, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        responseType: 'blob', // Expect PDF blob response
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          // Scale upload to be 0-30% of total progress
          setProgress(Math.min(30, percentCompleted * 0.3));
        },
        onDownloadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            // Scale download to be 80-100% of total progress
            setProgress(80 + (percentCompleted * 0.2));
          }
        }
      });

      if (response.status === 200) {
        clearInterval(interval);
        setProgress(100);
        setPdfBlob(response.data);
        setStatus('done');
      } else {
        clearInterval(interval);
        throw new Error('Analysis failed.');
      }

    } catch (error) {
      console.error("Error during analysis:", error);
      setStatus('error');
      setErrorMessage(error.response?.data?.detail || error.message || "An unexpected error occurred.");
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    // Accept standard file types requested, plus generic things
    accept: {
      'application/json': ['.json'],
      'text/csv': ['.csv'],
      'text/xml': ['.xml', '.xmls'],
      'text/plain': ['.txt', '.log'],
      'application/zip': ['.zip', '.rar', '.7z']
    },
    // We remove the accept prop temporarily if you want to support *folders* natively without OS restrictions,
    // but react-dropzone supports folder drops using webkitGetAsEntry out of the box.
    // However, if we specify accept types, folders lacking an extension might be rejected.
    // For maximum compatibility with unstructured folder drops, let's omit the restrictive 'accept' filter,
    // or keep it but allow '*/*' if needed. Let's keep it null/undefined to allow folders seamlessly.
  });

  const handleDownload = () => {
    if (!pdfBlob) return;

    // Use file-saver for robust cross-browser downloading
    saveAs(pdfBlob, 'audit_report.pdf');
  };

  const resetState = () => {
    setStatus('idle');
    setPdfBlob(null);
    setProgress(0);
    setErrorMessage('');
  };

  if (initialLoad) {
    return (
      <div className="initial-loader">
        <div className="spinner"></div>
        <p style={{ marginTop: '1rem', fontWeight: 600, color: 'var(--text-main)' }}>Initializing Auditor Engine...</p>
      </div>
    );
  }

  return (
    <div className="app-container">
      <header className="header">
        <ShieldCheck className="logo-icon" size={28} />
        <span>AuditForge</span>
      </header>

      <main className="main-content">

        {status === 'idle' && (
          <>
            <section className="hero">
              <h1>Is your infrastructure secure enough?</h1>
              <p>
                A fast, fully offline AI-powered security audit engine that analyzes multi-format scan data and generates professional vulnerability reports — without sending your data to the cloud.
              </p>
            </section>

            <div
              {...getRootProps()}
              className={`dropzone ${isDragActive ? 'active' : ''}`}
            >
              <input {...getInputProps()} />
              <UploadCloud className="upload-icon" />
              <p className="dropzone-title">
                {isDragActive
                  ? "Drop the files here..."
                  : "Drag & drop files, folders, or ZIP here"}
              </p>
              <p className="dropzone-subtitle">or click to browse your files</p>

              <div className="supported-types">
                <span className="type-badge">.json</span>
                <span className="type-badge">.csv</span>
                <span className="type-badge">.xml</span>
                <span className="type-badge">.txt</span>
                <span className="type-badge">.log</span>
                <span className="type-badge">.zip</span>
                <span className="type-badge">folders</span>
              </div>
            </div>
          </>
        )}

        {status === 'processing' && (
          <div className="processing-container">
            <div className="progress-bar-bg" style={{ width: '100%', maxWidth: '400px', height: '12px', background: 'var(--border-color)', borderRadius: '999px', overflow: 'hidden', marginBottom: '1.5rem' }}>
              <div className="progress-bar-fill" style={{ width: `${progress}%`, height: '100%', background: 'var(--primary)', transition: 'width 0.3s ease' }}></div>
            </div>
            <h2 className="progress-text">Analyzing Infrastructure Data... {Math.round(progress)}%</h2>
            <p className="progress-subtext">The offline AI model is parsing files and identifying vulnerabilities.</p>
          </div>
        )}

        {status === 'done' && (
          <div className="success-container">
            <CheckCircle className="success-icon" />
            <h2 className="success-title">Analysis Complete</h2>
            <p className="success-text">Your professional vulnerability report is ready.</p>

            <button className="btn-primary" onClick={handleDownload}>
              <Download size={20} />
              Download Report PDF
            </button>

            <button className="btn-secondary" onClick={resetState}>
              Analyze Another Source
            </button>
          </div>
        )}

        {status === 'error' && (
          <div className="success-container" style={{ border: '2px solid #EF4444' }}>
            <FileType style={{ color: '#EF4444', width: 64, height: 64, marginBottom: '1rem' }} />
            <h2 className="success-title" style={{ color: '#EF4444' }}>Analysis Failed</h2>
            <p className="success-text">{errorMessage}</p>

            <button className="btn-secondary" onClick={resetState}>
              Try Again
            </button>
          </div>
        )}

      </main>
    </div>
  );
}

export default App;
