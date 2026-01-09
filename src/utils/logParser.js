/**
 * Log Parser
 * Handles different log formats and extracts relevant info
 * 
 * Supports: generic format, SSH logs, Apache/nginx logs
 * Author: Ava Raper
 */

// Helper to pull out IP addresses from log lines
export const extractIP = (logLine) => {
  const match = logLine.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return match ? match[1] : 'N/A';
};

// Get timestamp from various log formats
export const extractTimestamp = (logLine) => {
  // Try standard format first: YYYY-MM-DD HH:MM:SS
  const standardMatch = logLine.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
  if (standardMatch) return standardMatch[1];
  
  // Apache/nginx format: [DD/Mon/YYYY:HH:MM:SS]
  const apacheMatch = logLine.match(/\[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})/);
  if (apacheMatch) return apacheMatch[1];
  
  // Syslog format: Mon DD HH:MM:SS
  const syslogMatch = logLine.match(/(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
  if (syslogMatch) return syslogMatch[1];
  
  // If there is no time found, just use current time
  return new Date().toISOString();
};

// Pull out country/location if it's in the log
export const extractCountry = (logLine) => {
  const match = logLine.match(/\(([^)]+)\)/);
  return match ? match[1] : 'Unknown';
};

// Figure out how severe this log entry is
export const detectSeverity = (logLine) => {
  const line = logLine.toUpperCase();
  
  // Check if severity is explicitly stated
  const explicit = line.match(/\[(CRITICAL|HIGH|MEDIUM|LOW|FAILED|SUCCESS|INFO|WARNING|ERROR)\]/);
  if (explicit) return explicit[1];
  
  // Look for critical keywords
  if (line.includes('BRUTE FORCE') || 
      line.includes('SQL INJECTION') || 
      line.includes('MALWARE') ||
      line.includes('EXPLOIT')) {
    return 'CRITICAL';
  }
  
  // High severity stuff
  if (line.includes('PORT SCAN') || 
      line.includes('XSS') || 
      line.includes('DDOS') ||
      line.includes('UNAUTHORIZED')) {
    return 'HIGH';
  }
  
  // Medium priority
  if (line.includes('SUSPICIOUS') || 
      line.includes('UNUSUAL')) {
    return 'MEDIUM';
  }
  
  // Failed attempts
  if (line.includes('FAILED') || 
      line.includes('DENIED')) {
    return 'FAILED';
  }
  
  // Success
  if (line.includes('SUCCESS') || 
      line.includes('ACCEPTED')) {
    return 'SUCCESS';
  }
  
  return 'INFO';
};

// Parse a generic security log line
export const parseGenericLog = (logLine) => {
  const timestamp = extractTimestamp(logLine);
  const severity = detectSeverity(logLine);
  const ip = extractIP(logLine);
  const country = extractCountry(logLine);
  
  // Consider it a threat if it's critical, high, or a failure
  const isThreat = ['CRITICAL', 'HIGH', 'FAILED'].includes(severity);
  
  return {
    timestamp,
    severity,
    ip,
    country,
    raw: logLine,
    isThreat,
    type: 'generic'
  };
};

// Parse SSH authentication logs
export const parseSSHLog = (logLine) => {
  const timestamp = extractTimestamp(logLine);
  const ip = extractIP(logLine);
  
  let severity = 'INFO';
  let isThreat = false;
  
  // Check what happened
  if (logLine.toLowerCase().includes('failed password')) {
    severity = 'FAILED';
    isThreat = true;
  } else if (logLine.toLowerCase().includes('accepted password')) {
    severity = 'SUCCESS';
  } else if (logLine.toLowerCase().includes('invalid user')) {
    severity = 'HIGH';
    isThreat = true;
  }
  
  // Try to get the username
  const userMatch = logLine.match(/(?:for|user)\s+(\w+)/i);
  const username = userMatch ? userMatch[1] : 'unknown';
  
  return {
    timestamp,
    severity,
    ip,
    country: 'Unknown',
    username,
    raw: logLine,
    isThreat,
    type: 'ssh'
  };
};

// Parse Apache/nginx access logs
export const parseApacheLog = (logLine) => {
  const timestamp = extractTimestamp(logLine);
  const ip = extractIP(logLine);
  
  // Get HTTP status code
  const statusMatch = logLine.match(/"\s+(\d{3})\s+/);
  const status = statusMatch ? parseInt(statusMatch[1]) : 0;
  
  // Get request method and path
  const requestMatch = logLine.match(/"(\w+)\s+([^\s]+)\s+HTTP/);
  const method = requestMatch ? requestMatch[1] : 'UNKNOWN';
  const path = requestMatch ? requestMatch[2] : '/';
  
  let severity = 'INFO';
  let isThreat = false;
  
  // 4xx and 5xx errors are potential issues
  if (status >= 400 && status < 500) {
    severity = 'MEDIUM';
    isThreat = true;
  }
  if (status >= 500) {
    severity = 'HIGH';
    isThreat = true;
  }
  
  // Check for SQL injection patterns in the URL
  if (path.match(/union.*select|insert.*into|delete.*from/i)) {
    severity = 'CRITICAL';
    isThreat = true;
  }
  
  // XSS attempts
  if (path.match(/<script|javascript:/i)) {
    severity = 'HIGH';
    isThreat = true;
  }
  
  // Directory traversal
  if (path.includes('..')) {
    severity = 'HIGH';
    isThreat = true;
  }
  
  return {
    timestamp,
    severity,
    ip,
    country: 'Unknown',
    status,
    method,
    path,
    raw: logLine,
    isThreat,
    type: 'apache'
  };
};

// nginx logs are basically the same as Apache
export const parseNginxLog = (logLine) => {
  const parsed = parseApacheLog(logLine);
  parsed.type = 'nginx';
  return parsed;
};

// Main parsing function - tries to figure out the format automatically
export const parseLog = (logLine) => {
  if (!logLine || !logLine.trim()) {
    return null;
  }
  
  const line = logLine.trim();
  
  // SSH log detection
  if (line.includes('sshd')) {
    return parseSSHLog(line);
  }
  
  // Apache/nginx log detection (starts with IP and has HTTP method)
  if (line.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*"(GET|POST|PUT|DELETE)/)) {
    return parseApacheLog(line);
  }
  
  // Default to generic parser
  return parseGenericLog(line);
};

// Parse multiple lines at once
export const parseLogs = (logLines) => {
  if (!Array.isArray(logLines)) {
    return [];
  }
  
  return logLines
    .map(line => parseLog(line))
    .filter(log => log !== null);
};

// Sample data for demo only
export const sampleLogs = [
  '2026-01-07 14:23:45 [CRITICAL] Multiple SSH brute force attempts from 45.142.120.10 (Russia) - 15 failed attempts in 30s',
  '2026-01-07 14:23:47 [FAILED] Login attempt from 192.168.1.105 - user: admin',
  '2026-01-07 14:23:49 [CRITICAL] SQL injection attempt detected from 185.220.101.33 (Netherlands) in /api/users',
  '2026-01-07 14:24:12 [SUCCESS] Login from 10.0.0.45 (US) - user: jsmith',
  '2026-01-07 14:25:33 [HIGH] Port scan detected from 203.0.113.42 (Unknown) - scanning ports 22, 80, 443, 3306',
  '2026-01-07 14:26:01 [FAILED] Login attempt from 198.51.100.88 (China) - user: admin',
  '2026-01-07 14:27:15 [MEDIUM] Suspicious user-agent detected from 91.108.56.181 (Germany)',
  '2026-01-07 14:28:45 [SUCCESS] Login from 10.0.0.67 (US) - user: mjones',
  '2026-01-07 14:30:22 [HIGH] XSS attempt blocked from 203.0.113.42 in search parameter',
  '2026-01-07 14:32:11 [FAILED] Login attempt from 192.168.1.105 - user: root',
  '2026-01-07 14:35:44 [CRITICAL] Directory traversal attempt from 185.220.101.33 (Netherlands) - blocked',
  '2026-01-07 14:38:19 [INFO] Successful API authentication from 10.0.0.45 (US)',
  '2026-01-07 14:42:03 [HIGH] Excessive requests detected from 45.142.120.10 (Russia) - possible DDoS',
  '2026-01-07 14:45:27 [FAILED] Login attempt from 185.220.101.33 (Netherlands) - user: administrator',
  '2026-01-07 14:47:12 [CRITICAL] Malware signature detected in uploaded file from 198.51.100.88 (China)',
  '2026-01-07 14:50:33 [MEDIUM] Unusual outbound connection to 203.0.113.42 on port 4444',
  '2026-01-07 14:52:15 [INFO] Firewall rule updated - blocking 45.142.120.10',
  '2026-01-07 14:55:01 [HIGH] Privilege escalation attempt detected from internal IP 10.0.0.89'
];

// Geographic data for the attack map
export const geoLocations = {
  'Russia': { lat: 55.7558, lng: 37.6173, attacks: 0 },
  'China': { lat: 39.9042, lng: 116.4074, attacks: 0 },
  'Netherlands': { lat: 52.3676, lng: 4.9041, attacks: 0 },
  'Germany': { lat: 52.5200, lng: 13.4050, attacks: 0 },
  'US': { lat: 37.7749, lng: -122.4194, attacks: 0, friendly: true },
  'Unknown': { lat: 0, lng: 0, attacks: 0 }
};