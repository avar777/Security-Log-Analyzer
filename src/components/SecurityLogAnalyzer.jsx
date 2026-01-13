/**
 * Security Log Analyzer
 * The main component 
 * 
 * Author: Ava Raper
 */

import React, { useState, useEffect } from 'react';
import { Shield, Upload, Lock, Eye, AlertTriangle } from 'lucide-react';
import ThreatMeter from './ThreatMeter';
import AlertPanel from './AlertPanel';
import AttackMap from './AttackMap';
import Tutorial from './Tutorial';
import { parseLogs, sampleLogs, geoLocations } from '../utils/logParser';
import { analyzeLogs } from '../utils/threatAnalysis';
import '../styles/Dashboard.css';

const SecurityLogAnalyzer = () => {
  const [analysis, setAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Load the sample data for demo (delete this later)
  useEffect(() => {
    setIsAnalyzing(true);
    
    // Give it a second to feel like it's actually analyzing
    setTimeout(() => {
      const parsed = parseLogs(sampleLogs);
      const results = analyzeLogs(parsed, geoLocations);
      setAnalysis(results);
      
      setIsAnalyzing(false);
    }, 1200);
  }, []);

  // Handle file upload
  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target.result;
      const lines = content.split('\n').filter(line => line.trim());
      
      setIsAnalyzing(true);
      
      // Parse the uploaded logs
      setTimeout(() => {
        const parsed = parseLogs(lines);
        const results = analyzeLogs(parsed, geoLocations);
        setAnalysis(results);
        
        setIsAnalyzing(false);
      }, 800);
    };
    
    reader.readAsText(file);
  };

  if (isAnalyzing) {
    return (
      <div className="analyzer-loading">
        <div className="loading-content">
          <div className="loading-spinner"></div>
          <h2>Analyzing logs...</h2>
          <p>This'll just take a sec</p>
        </div>
      </div>
    );
  }

  if (!analysis) {
    return null;
  }

  return (
    <div className="security-analyzer">
      <div className="analyzer-content">
        {/* Header */}
        <div className="analyzer-header">
          <div className="header-title">
            <h1>Security Log Analyzer</h1>
          </div>
          
          <div className="header-actions">
            <Tutorial />
            
            <label className="upload-button">
              <div className="upload-button-content">
                <Upload size={18} />
              </div>
              <input 
                type="file" 
                accept=".log,.txt" 
                onChange={handleFileUpload} 
                className="upload-input" 
              />
            </label>
          </div>
        </div>

        {/* Threat level bar */}
        <ThreatMeter threatLevel={analysis.threatLevel} />

        {/* Quick stats - removed Total Events */}
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-header">
              <AlertTriangle size={20} className="stat-icon" />
            </div>
            <div className="stat-value" style={{ color: '#d98572' }}>
              {analysis.stats.criticalAlerts}
            </div>
            <div className="stat-label">Critical Alerts</div>
          </div>
          
          <div className="stat-card">
            <div className="stat-header">
              <Lock size={20} className="stat-icon" />
            </div>
            <div className="stat-value" style={{ color: '#e8b55d' }}>
              {analysis.stats.failedLogins}
            </div>
            <div className="stat-label">Failed Logins</div>
          </div>
          
          <div className="stat-card">
            <div className="stat-header">
              <Shield size={20} className="stat-icon" />
            </div>
            <div className="stat-value">{analysis.stats.blockedIPs}</div>
            <div className="stat-label">Blocked IPs</div>
          </div>
          
          <div className="stat-card">
            <div className="stat-header">
              <Eye size={20} className="stat-icon" />
            </div>
            <div className="stat-value" style={{ color: '#e8b55d' }}>
              {analysis.stats.activeThreats}
            </div>
            <div className="stat-label">Active Threats</div>
          </div>
        </div>

        {/* Attack origins map */}
        <AttackMap attackData={analysis.attackMap} />

        {/* Security alerts - now scrollable */}
        <AlertPanel alerts={analysis.alerts} />
      </div>
    </div>
  );
};

export default SecurityLogAnalyzer;