/**
 * Threat Analysis
 * Analyzes parsed logs and generates threat scores and alerts
 * 
 * TODO: add more sophisticated pattern detection
 * TODO: maybe integrate with threat intelligence feeds?
 */

// Calculate overall threat score (0-100)
export const calculateThreatScore = (logs) => {
  if (!logs || logs.length === 0) return 0;
  
  let score = 0;
  
  logs.forEach(log => {
    // Add points based on severity
    if (log.severity === 'CRITICAL') score += 10;
    else if (log.severity === 'HIGH') score += 5;
    else if (log.severity === 'MEDIUM') score += 2;
    else if (log.severity === 'FAILED') score += 2;
  });
  
  // Normalize to 0-100
  const maxPossible = logs.length * 10;
  const normalized = Math.min(100, (score / maxPossible) * 100);
  
  return Math.round(normalized);
};

// Look for brute force attacks (multiple failures from same IP)
export const detectBruteForce = (logs) => {
  const ipFailures = {};
  const alerts = [];
  
  // Count failures per IP
  logs.forEach(log => {
    if (log.severity === 'FAILED' && log.ip !== 'N/A') {
      if (!ipFailures[log.ip]) {
        ipFailures[log.ip] = [];
      }
      ipFailures[log.ip].push(log);
    }
  });
  
  // Flag IPs with 3+ failures
  Object.entries(ipFailures).forEach(([ip, failures]) => {
    if (failures.length >= 3) {
      alerts.push({
        type: 'brute_force',
        severity: 'critical',
        ip,
        count: failures.length,
        message: `Brute force attack detected from ${ip} - ${failures.length} failed attempts`,
        timestamp: failures[failures.length - 1].timestamp,
        country: failures[0].country
      });
    }
  });
  
  return alerts;
};

// Detect SQL injection attempts
export const detectSQLInjection = (logs) => {
  const alerts = [];
  
  logs.forEach(log => {
    const line = log.raw.toLowerCase();
    
    // Look for SQL injection keywords
    if (line.includes('sql injection') ||
        line.includes('union select') ||
        line.includes('drop table') ||
        (log.path && log.path.match(/union.*select|drop.*table/i))) {
      alerts.push({
        type: 'sql_injection',
        severity: 'critical',
        ip: log.ip,
        message: `SQL injection attempt from ${log.ip}`,
        timestamp: log.timestamp,
        country: log.country
      });
    }
  });
  
  return alerts;
};

// Detect port scanning
export const detectPortScan = (logs) => {
  const alerts = [];
  
  logs.forEach(log => {
    if (log.raw.toLowerCase().includes('port scan')) {
      alerts.push({
        type: 'port_scan',
        severity: 'high',
        ip: log.ip,
        message: `Port scanning detected from ${log.ip}`,
        timestamp: log.timestamp,
        country: log.country
      });
    }
  });
  
  return alerts;
};

// Detect XSS attempts
export const detectXSS = (logs) => {
  const alerts = [];
  
  logs.forEach(log => {
    const line = log.raw.toLowerCase();
    
    if (line.includes('xss') ||
        line.includes('<script') ||
        (log.path && log.path.includes('<script'))) {
      alerts.push({
        type: 'xss',
        severity: 'high',
        ip: log.ip,
        message: `XSS attempt from ${log.ip}`,
        timestamp: log.timestamp,
        country: log.country
      });
    }
  });
  
  return alerts;
};

// Detect directory traversal
export const detectDirectoryTraversal = (logs) => {
  const alerts = [];
  
  logs.forEach(log => {
    if (log.raw.includes('..') || 
        (log.path && log.path.includes('..'))) {
      alerts.push({
        type: 'directory_traversal',
        severity: 'high',
        ip: log.ip,
        message: `Directory traversal attempt from ${log.ip}`,
        timestamp: log.timestamp,
        country: log.country
      });
    }
  });
  
  return alerts;
};

// Detect potential DDoS (lots of requests from one IP)
export const detectDDoS = (logs) => {
  const ipCounts = {};
  const alerts = [];
  
  // Count requests per IP
  logs.forEach(log => {
    if (log.ip !== 'N/A') {
      ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1;
    }
  });
  
  // Flag IPs with excessive requests
  const threshold = Math.max(10, logs.length * 0.1);
  
  Object.entries(ipCounts).forEach(([ip, count]) => {
    if (count > threshold) {
      const ipLogs = logs.filter(l => l.ip === ip);
      alerts.push({
        type: 'ddos',
        severity: 'high',
        ip,
        count,
        message: `Possible DDoS from ${ip} - ${count} requests`,
        timestamp: ipLogs[ipLogs.length - 1].timestamp,
        country: ipLogs[0].country
      });
    }
  });
  
  return alerts;
};

// Generate all alerts from logs
export const generateAlerts = (logs) => {
  // Run all the detection functions
  const allAlerts = [
    ...detectBruteForce(logs),
    ...detectSQLInjection(logs),
    ...detectPortScan(logs),
    ...detectXSS(logs),
    ...detectDirectoryTraversal(logs),
    ...detectDDoS(logs)
  ];
  
  // Also add explicit high/critical logs as alerts
  logs.forEach(log => {
    if ((log.severity === 'CRITICAL' || log.severity === 'HIGH') && log.isThreat) {
      // Make sure we don't duplicate
      const exists = allAlerts.some(a => 
        a.ip === log.ip && a.timestamp === log.timestamp
      );
      
      if (!exists) {
        allAlerts.push({
          type: 'general',
          severity: log.severity.toLowerCase(),
          ip: log.ip,
          message: log.raw.split('] ')[1] || log.raw,
          timestamp: log.timestamp,
          country: log.country
        });
      }
    }
  });
  
  // Sort by severity (critical first)
  return allAlerts.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity];
  });
};

// Aggregate stats from logs
export const aggregateStats = (logs) => {
  const stats = {
    totalEvents: logs.length,
    criticalAlerts: 0,
    highAlerts: 0,
    failedLogins: 0,
    successfulLogins: 0,
    blockedIPs: new Set(),
    activeThreats: 0,
    uniqueIPs: new Set(),
    countries: {}
  };
  
  logs.forEach(log => {
    // Count by severity
    if (log.severity === 'CRITICAL') stats.criticalAlerts++;
    if (log.severity === 'HIGH') stats.highAlerts++;
    if (log.severity === 'FAILED') stats.failedLogins++;
    if (log.severity === 'SUCCESS') stats.successfulLogins++;
    
    // Track IPs
    if (log.ip !== 'N/A') {
      stats.uniqueIPs.add(log.ip);
      if (log.isThreat) {
        stats.blockedIPs.add(log.ip);
      }
    }
    
    // Count by country
    if (log.country && log.country !== 'Unknown') {
      stats.countries[log.country] = (stats.countries[log.country] || 0) + 1;
    }
  });
  
  // Active threats = critical + high
  stats.activeThreats = stats.criticalAlerts + stats.highAlerts;
  
  return {
    totalEvents: stats.totalEvents,
    criticalAlerts: stats.criticalAlerts,
    failedLogins: stats.failedLogins,
    blockedIPs: stats.blockedIPs.size,
    activeThreats: stats.activeThreats,
    uniqueIPs: stats.uniqueIPs.size,
    countries: stats.countries
  };
};

// Build attack map data
export const buildAttackMap = (logs, geoLocations) => {
  const countryCounts = {};
  
  // Count threats by country
  logs.forEach(log => {
    if (log.country && log.country !== 'Unknown' && log.isThreat) {
      countryCounts[log.country] = (countryCounts[log.country] || 0) + 1;
    }
  });
  
  // Merge with geo data
  const mapData = Object.entries(geoLocations).map(([country, coords]) => ({
    country,
    ...coords,
    attacks: countryCounts[country] || 0
  }));
  
  // Only return countries with attacks
  return mapData.filter(loc => loc.attacks > 0);
};

// Get top attacking IPs
export const getTopAttackingIPs = (logs, limit = 5) => {
  const ipCounts = {};
  
  logs.forEach(log => {
    if (log.isThreat && log.ip !== 'N/A') {
      if (!ipCounts[log.ip]) {
        ipCounts[log.ip] = { count: 0, country: log.country };
      }
      ipCounts[log.ip].count++;
    }
  });
  
  return Object.entries(ipCounts)
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
};

// Main analysis function - does everything
export const analyzeLogs = (logs, geoLocations) => {
  if (!logs || logs.length === 0) {
    return {
      threatLevel: 0,
      stats: {
        totalEvents: 0,
        criticalAlerts: 0,
        failedLogins: 0,
        blockedIPs: 0,
        activeThreats: 0
      },
      alerts: [],
      attackMap: [],
      topIPs: []
    };
  }
  
  const threatLevel = calculateThreatScore(logs);
  const stats = aggregateStats(logs);
  const alerts = generateAlerts(logs);
  const attackMap = buildAttackMap(logs, geoLocations);
  const topIPs = getTopAttackingIPs(logs);
  
  return {
    threatLevel,
    stats,
    alerts,
    attackMap,
    topIPs
  };
};