/**
 * Help Tutorial Card
 * Guide for how to use the Security Log Analyzer
 * 
 * Author: Ava Raper
 */

import React, { useState } from 'react';
import { HelpCircle, X} from 'lucide-react';

const HelpTutorial = () => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      {/* Help button */}
      <button 
        className="help-button"
        onClick={() => setIsOpen(true)}
        title="Learn how to use this tool"
      >
        <HelpCircle size={20} />
      </button>

      {/* Tutorial pop-up */}
      {isOpen && (
        <div className="tutorial-overlay" onClick={() => setIsOpen(false)}>
          <div className="tutorial-modal" onClick={(e) => e.stopPropagation()}>
            <button 
              className="tutorial-close"
              onClick={() => setIsOpen(false)}
            >
              <X size={24} />
            </button>

            <div className="tutorial-content">
              <h2>Help Guide</h2>
              <p className="tutorial-intro">
                This website allows the user to upload a txt or log file. Once the files are uploaded it will analyze
                the security logs and identifies threats like hacking attempts, 
                brute force attacks, and suspicious activity.
              </p>

              {/* What the display means*/}
              <div className="tutorial-section">
                <div className="tutorial-section-header">
                  <h3>Reading the Website</h3>
                </div>
                
                <p><strong>Threat Level:</strong></p>
                <ul>
                  <li><span className="status-low">Low (0-40%):</span> This is normal activity</li>
                  <li><span className="status-elevated">Elevated (40-60%):</span> Some suspicious activity detected</li>
                  <li><span className="status-high">High (60-80%):</span> There are multiple threats detected</li>
                  <li><span className="status-critical">Critical (80-100%):</span> Immediate attention is needed</li>
                </ul>

                <p><strong>Quick Statistics:</strong></p>
                <ul>
                  <li>The stats are each self labeled and describe what happened in the log through
                    a quick glance. 
                  </li>
                </ul>

                <p><strong>Attack Map:</strong></p>
                <ul>
                  <li>This is a cyber attack map showing where threats are coming from geographically. 
                    The larger and more intense the red dots, the more attacks originating from that location.
                  </li>
                </ul>

                <p><strong>Security Alerts:</strong></p>
                <ul>
                  <li><span className="severity-success">NORMAL</span> - Normal, authorized activity</li>
                  <li><span className="severity-failed">LOW</span> - Failed login attempts (possible brute force)</li>
                  <li><span className="severity-medium">MEDIUM</span> - Suspicious but not urgent</li>
                  <li><span className="severity-high">HIGH</span> - Major concerns (port scans, XSS attempts)</li>
                  <li><span className="severity-critical">CRITICAL</span> - Serious attacks (SQL injection, malware)</li>
                </ul>
              </div>

              {/* What to look for */}
              <div className="tutorial-section">
                <div className="tutorial-section-header">
                  <h3>What to Look For</h3>
                </div>
                <p><strong>Red flags:</strong></p>
                <ul>
                  <li>Threat level above 60%</li>
                  <li>Multiple failed logins from the same IP address</li>
                  <li>Critical or High severity alerts</li>
                  <li>Lots of requests from unfamiliar countries</li>
                </ul>

                <p><strong>Common Attack Types:</strong></p>
                <ul>
                  <li><strong>Brute Force:</strong> Repeated password guessing attempts</li>
                  <li><strong>SQL Injection:</strong> Trying to manipulate the database with malicious code</li>
                  <li><strong>Port Scan:</strong> Checking which network ports are open (often before an attack)</li>
                  <li><strong>XSS:</strong> Injecting malicious scripts into web pages</li>
                  <li><strong>DDoS:</strong> Overwhelming the server with traffic to take it offline</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default HelpTutorial;