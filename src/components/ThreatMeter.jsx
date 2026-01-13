/**
 * Threat Meter Card
 * Shows current threat level as a progress bar with a percentage
 * 
 * Author: Ava Raper
 */

import React from 'react';
import { TrendingUp } from 'lucide-react';

const ThreatMeter = ({ threatLevel }) => {
  // Figure out what color the bar will be
  const getThreatColor = () => {
    if (threatLevel < 40) return '#7a9b7f'; // green - all good
    if (threatLevel < 60) return '#e8b55d'; // yellow - keep an eye out
    if (threatLevel < 80) return '#e89a5d'; // orange - not great
    return '#d98572'; // red - bad
  };

  return (
    <div className="threat-meter-container">
      <div className="threat-meter-header">
        <div className="threat-meter-title">
          <TrendingUp size={20} />
          <h2>Threat Level</h2>
        </div>
        <div 
          className="threat-meter-value" 
          style={{ color: getThreatColor() }}
        >
          {Math.round(threatLevel)}%
        </div>
      </div>
      
      <div className="threat-meter-bar-container">
        <div 
          className="threat-meter-bar"
          style={{ 
            width: `${threatLevel}%`,
            backgroundColor: getThreatColor()
          }}
        />
      </div>
      
      <div className="threat-meter-labels">
        <span>Low</span>
        <span>Elevated</span>
        <span>High</span>
        <span>Critical</span>
      </div>
      
    </div>
  );
};

export default ThreatMeter;