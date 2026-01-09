/**
 * Alert Card
 * Shows all security alerts in a scrollable car 
 * 
 * Author: Ava Raper
 */

import React from 'react';
import { AlertTriangle } from 'lucide-react';

const AlertPanel = ({ alerts }) => {
  const getSeverityColor = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'critical': 
        return '#d98572';
      case 'high': 
        return '#e8b55d';
      case 'medium': 
        return '#e8b55d';
      default: 
        return '#6b7f7f';
    }
  };

  // The panel won't show if there are no alerts
  if (!alerts || alerts.length === 0) {
    return null;
  }

  return (
    <div className="alert-panel-container">
      <div className="alert-panel-header">
        <AlertTriangle size={18} />
        <h3>Security Alerts</h3>
        <div className="alert-count">
          {alerts.length}
        </div>
      </div>
      
      {/* Shows all alerts and is scrollable */}
      <div className="alert-panel-scroll">
        <div className="alert-panel-grid">
          {alerts.map((alert, idx) => (
            <div 
              key={idx} 
              className="alert-item"
              style={{ borderLeftColor: getSeverityColor(alert.severity) }}
            >
              <div className="alert-content">
                <AlertTriangle 
                  size={18}
                  className="alert-icon"
                  style={{ color: getSeverityColor(alert.severity) }}
                />
                <div className="alert-details">
                  <div className="alert-message">{alert.message}</div>
                  <div className="alert-meta">
                    <span>{alert.timestamp}</span>
                    <span>•</span>
                    <span>{alert.ip}</span>
                    {alert.country && alert.country !== 'Unknown' && (
                      <>
                        <span>•</span>
                        <span>{alert.country}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AlertPanel;