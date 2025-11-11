import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../utils/api';

function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [polling, setPolling] = useState(false);

  useEffect(() => {
    fetchScan();
  }, [id]);

  useEffect(() => {
    if (polling && scan && (scan.status === 'queued' || scan.status === 'running')) {
      const interval = setInterval(() => {
        fetchScan();
      }, 2000); // Poll more frequently for progress updates
      return () => clearInterval(interval);
    }
  }, [polling, scan]);

  const fetchScan = async () => {
    try {
      const response = await api.get(`/api/scans/${id}/status`);
      setScan(response.data);
      
      if (response.data.status === 'queued' || response.data.status === 'running') {
        setPolling(true);
      } else if (response.data.status === 'done') {
        setPolling(false);
        fetchResult();
      }
    } catch (err) {
      console.error('Failed to fetch scan:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchResult = async () => {
    try {
      const response = await api.get(`/api/scans/${id}/result`);
      setResult(response.data);
    } catch (err) {
      console.error('Failed to fetch result:', err);
    }
  };

  const downloadPDF = async () => {
    try {
      const response = await api.get(`/api/scans/${id}/report.pdf`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan_${id}_report.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert('Failed to download PDF');
    }
  };

  const downloadJSON = async () => {
    try {
      const response = await api.get(`/api/scans/${id}/result`);
      const dataStr = JSON.stringify(response.data, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = window.URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan_${id}_result.json`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert('Failed to download JSON');
    }
  };

  const downloadRecommendations = async (format) => {
    try {
      const response = await api.get(`/api/scans/${id}/recommendations/export?format=${format}`);
      const dataStr = JSON.stringify(response.data, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = window.URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan_${id}_recommendations_${format}.json`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert(`Failed to export recommendations as ${format}`);
    }
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  if (!scan) {
    return <div className="container">Scan not found</div>;
  }

  return (
    <div className="container">
      <div style={{ marginBottom: '20px' }}>
        <Link to="/scans" className="btn btn-secondary">← Back to Scans</Link>
      </div>

      <div className="card">
        <h2>Scan Details</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
          <div>
            <strong>Target:</strong> {scan.target || 'N/A'}
          </div>
          <div>
            <strong>Status:</strong>{' '}
            <span className={`status-${scan.status}`}>{scan.status}</span>
          </div>
          <div>
            <strong>Created:</strong>{' '}
            {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
          </div>
          <div>
            <strong>Started:</strong>{' '}
            {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}
          </div>
          <div>
            <strong>Finished:</strong>{' '}
            {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : 'N/A'}
          </div>
          {scan.error_message && (
            <div style={{ gridColumn: '1 / -1' }}>
              <strong>Error:</strong>{' '}
              <span style={{ color: '#dc3545' }}>{scan.error_message}</span>
            </div>
          )}
        </div>

        {scan.status === 'done' && result && (
          <>
            <div style={{ marginBottom: '20px' }}>
              <h3>PQ Score: {result.pq_score} ({result.pq_level})</h3>
              <div style={{ marginTop: '10px' }}>
                <button className="btn btn-primary" onClick={downloadPDF} style={{ marginRight: '10px' }}>
                  Download PDF
                </button>
                <button className="btn btn-secondary" onClick={downloadJSON}>
                  Download JSON
                </button>
              </div>
            </div>

            <div className="card" style={{ marginTop: '20px' }}>
              <h3>Summary</h3>
              <p><strong>Total Findings:</strong> {result.summary.total_findings}</p>
              <p><strong>By Severity:</strong></p>
              <ul>
                <li>P0 (Critical): {result.summary.by_severity.P0}</li>
                <li>P1 (High): {result.summary.by_severity.P1}</li>
                <li>P2 (Medium): {result.summary.by_severity.P2}</li>
                <li>P3 (Low): {result.summary.by_severity.P3}</li>
              </ul>
            </div>

            <div className="card" style={{ marginTop: '20px' }}>
              <h3>Findings</h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Asset Type</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {result.findings.length === 0 ? (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', padding: '40px' }}>
                        No findings
                      </td>
                    </tr>
                  ) : (
                    result.findings.map((finding) => (
                      <tr key={finding.id}>
                        <td>
                          <span className={`badge ${
                            finding.severity === 'P0' ? 'badge-danger' :
                            finding.severity === 'P1' ? 'badge-warning' :
                            finding.severity === 'P2' ? 'badge-info' : 'badge-secondary'
                          }`}>
                            {finding.severity}
                          </span>
                        </td>
                        <td>{finding.category}</td>
                        <td>{finding.asset_type}</td>
                        <td>{finding.evidence || '-'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {result.recommendations && result.recommendations.length > 0 && (
              <div className="card" style={{ marginTop: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                  <h3>Recommendations</h3>
                  <div>
                    <button 
                      className="btn btn-secondary" 
                      onClick={() => downloadRecommendations('json')}
                      style={{ marginRight: '5px', padding: '5px 10px', fontSize: '12px' }}
                    >
                      Export JSON
                    </button>
                    <button 
                      className="btn btn-secondary" 
                      onClick={() => downloadRecommendations('jira')}
                      style={{ marginRight: '5px', padding: '5px 10px', fontSize: '12px' }}
                    >
                      Export Jira
                    </button>
                    <button 
                      className="btn btn-secondary" 
                      onClick={() => downloadRecommendations('github')}
                      style={{ padding: '5px 10px', fontSize: '12px' }}
                    >
                      Export GitHub
                    </button>
                  </div>
                </div>
                {result.recommendations.map((rec) => (
                  <div key={rec.id} style={{ 
                    border: '1px solid #ddd', 
                    borderRadius: '4px', 
                    padding: '15px', 
                    marginBottom: '15px',
                    background: rec.priority === 'P0' ? '#fff5f5' : rec.priority === 'P1' ? '#fffbf0' : '#f8f9fa'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '10px' }}>
                      <div>
                        <span className={`badge ${
                          rec.priority === 'P0' ? 'badge-danger' :
                          rec.priority === 'P1' ? 'badge-warning' :
                          rec.priority === 'P2' ? 'badge-info' : 'badge-secondary'
                        }`} style={{ marginRight: '10px' }}>
                          {rec.priority}
                        </span>
                        <strong>{rec.short_description}</strong>
                      </div>
                      <span className="badge badge-info">{rec.status}</span>
                    </div>
                    <div style={{ marginTop: '10px' }}>
                      <p><strong>Effort:</strong> {rec.effort_estimate}</p>
                      <p><strong>Confidence:</strong> {rec.confidence_score}%</p>
                    </div>
                    <details style={{ marginTop: '10px' }}>
                      <summary style={{ cursor: 'pointer', fontWeight: 'bold' }}>Technical Steps</summary>
                      <pre style={{ 
                        background: '#f5f5f5', 
                        padding: '10px', 
                        borderRadius: '4px', 
                        marginTop: '10px',
                        whiteSpace: 'pre-wrap',
                        fontSize: '12px'
                      }}>{rec.technical_steps}</pre>
                    </details>
                    {rec.verification_steps && (
                      <details style={{ marginTop: '10px' }}>
                        <summary style={{ cursor: 'pointer', fontWeight: 'bold' }}>Verification Steps</summary>
                        <pre style={{ 
                          background: '#f5f5f5', 
                          padding: '10px', 
                          borderRadius: '4px', 
                          marginTop: '10px',
                          whiteSpace: 'pre-wrap',
                          fontSize: '12px'
                        }}>{rec.verification_steps}</pre>
                      </details>
                    )}
                    {rec.rollback_notes && (
                      <details style={{ marginTop: '10px' }}>
                        <summary style={{ cursor: 'pointer', fontWeight: 'bold' }}>Rollback Notes</summary>
                        <p style={{ marginTop: '10px' }}>{rec.rollback_notes}</p>
                      </details>
                    )}
                    {rec.compliance_mapping && (
                      <p style={{ marginTop: '10px', fontSize: '12px', color: '#666' }}>
                        <strong>Compliance:</strong> {rec.compliance_mapping}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {(scan.status === 'queued' || scan.status === 'running') && (
          <div className="card" style={{ marginTop: '20px' }}>
            <h3>Сканирование в процессе...</h3>
            {scan.progress && (
              <div style={{ marginTop: '15px' }}>
                <div style={{ 
                  background: '#f0f0f0', 
                  borderRadius: '4px', 
                  height: '24px', 
                  marginBottom: '10px',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    background: scan.progress.progress >= 80 ? '#28a745' : 
                               scan.progress.progress >= 50 ? '#ffc107' : '#007bff',
                    height: '100%',
                    width: `${scan.progress.progress || 0}%`,
                    transition: 'width 0.3s ease',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'white',
                    fontSize: '12px',
                    fontWeight: 'bold'
                  }}>
                    {scan.progress.progress ? `${scan.progress.progress}%` : ''}
                  </div>
                </div>
                <div style={{ 
                  padding: '10px', 
                  background: '#f8f9fa', 
                  borderRadius: '4px',
                  fontSize: '14px'
                }}>
                  <strong>Этап:</strong> {scan.progress.stage || 'unknown'}<br/>
                  <strong>Статус:</strong> {scan.progress.message || 'Выполняется...'}
                </div>
              </div>
            )}
            {!scan.progress && (
              <div style={{ marginTop: '15px', color: '#666' }}>
                Ожидание начала сканирования...
              </div>
            )}
            <div style={{ marginTop: '15px', fontSize: '12px', color: '#999' }}>
              Страница автоматически обновится при завершении
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default ScanDetail;

