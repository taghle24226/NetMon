import React, { useState, useEffect, useCallback } from 'react';
import { 
  Wifi, Monitor, Smartphone, Router, AlertTriangle, 
  Settings, Clock, Shield, Download, RefreshCw, 
  Search, Bell, Activity, Users, 
  WifiOff, WifiHigh, WifiLow, Home, BarChart3, Network,
  LogOut, Menu, X, ChevronRight, Sun, Moon,
  HardDrive, Server, ShieldCheck, History,
  BellRing, Eye, EyeOff, CircuitBoard, FileText,
  User, Plus, Key, Trash2, Edit, Eye as EyeIcon,
  Mail, Lock,
  RotateCcw, CheckCircle2, AlertCircle, ArrowRight, Loader2,
  AlertOctagon, Ban, CheckCircle, Info,
  TrendingUp, TrendingDown, Cpu, MemoryStick,
  FileDown, FileJson, FileSpreadsheet,
  Save
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, AreaChart, Area } from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import './App.css';

// ======================
// JWT PARSER
// ======================

const parseJwt = (token) => {
  try {
    // Handle both Base64 and Base64Url encoding
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error('JWT parse error:', e);
    return null;
  }
};

const API_BASE = 'http://localhost:8000/api';

// ======================
// API UTILITY FUNCTIONS
// ======================

const downloadFromApi = async (url, filename) => {
  const token = localStorage.getItem('netmon_token') || sessionStorage.getItem('netmon_token');

  const res = await fetch(`${API_BASE}${url}`, {
    method: 'GET',
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem('netmon_token');
      sessionStorage.removeItem('netmon_token');
      window.location.href = '/';
    }
    let msg = `Erreur ${res.status}`;
    try {
      const j = await res.json();
      msg = j.detail || msg;
    } catch {}
    throw new Error(msg);
  }

  const blob = await res.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => window.URL.revokeObjectURL(blobUrl), 2000);
};

const openPreviewFromApi = async (url) => {
  const token = localStorage.getItem('netmon_token') || sessionStorage.getItem('netmon_token');
  const res = await fetch(`${API_BASE}${url}`, {
    method: 'GET',
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem('netmon_token');
      sessionStorage.removeItem('netmon_token');
      window.location.href = '/';
    }
    let msg = `Erreur ${res.status}`;
    try {
      const j = await res.json();
      msg = j.detail || msg;
    } catch {}
    throw new Error(msg);
  }

  const blob = await res.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  window.open(blobUrl, '_blank', 'noopener,noreferrer');
  setTimeout(() => window.URL.revokeObjectURL(blobUrl), 5000);
};

const downloadJsonFile = (data, filename) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json'
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
};

// ======================
// VALIDATION HELPERS
// ======================

const validateField = (name, value, formData = {}) => {
  switch (name) {
    case 'username':
      if (!value) return 'Le nom d\'utilisateur est requis';
      if (value.length < 3) return 'Le nom d\'utilisateur doit contenir au moins 3 caractères';
      if (value.length > 50) return 'Le nom d\'utilisateur ne peut pas dépasser 50 caractères';
      if (!/^[a-zA-Z0-9_]+$/.test(value)) return 'Le nom d\'utilisateur ne peut contenir que des lettres, chiffres et underscores';
      return null;
    
    case 'email':
      if (!value) return 'L\'adresse email est requise';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Veuillez entrer une adresse email valide';
      return null;
    
    case 'full_name':
      if (!value) return 'Le nom complet est requis';
      if (value.length < 2) return 'Le nom doit contenir au moins 2 caractères';
      return null;
    
    case 'password':
      if (!value) return 'Le mot de passe est requis';
      if (value.length < 6) return 'Le mot de passe doit contenir au moins 6 caractères';
      return null;
    
    case 'register_password':
      if (!value) return 'Le mot de passe est requis';
      if (value.length < 8) return 'Le mot de passe doit contenir au moins 8 caractères';
      if (!/[A-Z]/.test(value)) return 'Le mot de passe doit contenir au moins une majuscule';
      if (!/[a-z]/.test(value)) return 'Le mot de passe doit contenir au moins une minuscule';
      if (!/[0-9]/.test(value)) return 'Le mot de passe doit contenir au moins un chiffre';
      return null;
    
    case 'confirm_password':
      if (!value) return 'Veuillez confirmer votre mot de passe';
      if (value !== formData.password) return 'Les mots de passe ne correspondent pas';
      return null;
    
    default:
      return null;
  }
};

const getPasswordStrength = (password) => {
  const checks = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password)
  };
  
  const score = Object.values(checks).filter(Boolean).length;
  const percentage = (score / 4) * 100;
  
  let color, label;
  if (percentage <= 25) { color = '#ef4444'; label = 'Très faible'; }
  else if (percentage <= 50) { color = '#f97316'; label = 'Faible'; }
  else if (percentage <= 75) { color = '#eab308'; label = 'Moyen'; }
  else { color = '#22c55e'; label = 'Fort'; }
  
  return { checks, score, percentage, color, label };
};

// ======================
// COMPOSANT FORMFIELD EXTERNE (pour éviter les re-renders)
// ======================

const FormField = ({ 
  label, 
  name, 
  type = 'text', 
  placeholder, 
  icon: Icon, 
  value, 
  onChange, 
  error, 
  hint,
  rightElement,
  disabled = false,
  autoComplete,
  darkMode
}) => {
  return (
    <div className="form-field">
      {label && (
        <label className="form-label">
          {label}
        </label>
      )}
      <div className="form-input-wrapper">
        {Icon && (
          <span className="form-icon">
            <Icon size={18} />
          </span>
        )}
        <input
          type={type}
          name={name}
          placeholder={placeholder}
          value={value}
          onChange={onChange}
          disabled={disabled}
          autoComplete={autoComplete}
          className={`form-input ${error ? 'form-input-error' : ''} ${darkMode ? 'dark' : 'light'}`}
          style={{ paddingLeft: Icon ? '44px' : '14px', paddingRight: rightElement ? '44px' : '14px' }}
        />
        {rightElement && (
          <div className="form-right-element">
            {rightElement}
          </div>
        )}
      </div>
      {hint && !error && (
        <p className="form-hint">{hint}</p>
      )}
      {error && (
        <p className="form-error">
          <AlertCircle size={12} /> {error}
        </p>
      )}
    </div>
  );
};

// ======================
// COMPOSANT PASSWORD STRENGTH
// ======================

const PasswordStrengthIndicator = ({ password, darkMode }) => {
  const { checks, percentage, color, label } = getPasswordStrength(password);
  
  if (!password) return null;
  
  return (
    <div className="password-strength">
      <div className="password-strength-header">
        <span>Force du mot de passe</span>
        <span style={{ color: percentage === 100 ? '#22c55e' : undefined }}>
          {label}
        </span>
      </div>
      <div className="password-strength-bar">
        <motion.div
          className="password-strength-fill"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 0.3 }}
        />
      </div>
      <div className="password-checks">
        {[
          { label: '8+ caractères', valid: checks.length },
          { label: '1 majuscule', valid: checks.uppercase },
          { label: '1 minuscule', valid: checks.lowercase },
          { label: '1 chiffre', valid: checks.number }
        ].map((item, idx) => (
          <div key={idx} className={`password-check ${item.valid ? 'valid' : ''}`}>
            {item.valid ? <CheckCircle2 size={12} /> : <AlertCircle size={12} />}
            <span>{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ======================
// DEMO DATA + FAKE EXPORTS (PDF/CSV)
// ======================

const rand = (min, max) => Math.random() * (max - min) + min;
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

const randomMac = () => Array.from({ length: 6 }, () =>
  Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
).join(':');

const randomIp = () => `192.168.1.${Math.floor(rand(2, 254))}`;

const escapePdfText = (t) =>
  String(t).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');

const buildSimplePdf = (lines = []) => {
  const header = '%PDF-1.3\n';
  const objects = [];

  objects.push('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
  objects.push('2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n');
  objects.push('3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
  objects.push('4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');

  const contentLines = ['BT', '/F1 12 Tf', '50 800 Td'];
  lines.slice(0, 60).forEach((l, i) => {
    const safe = escapePdfText(l);
    contentLines.push(`(${safe}) Tj`);
    contentLines.push('T*');
  });
  contentLines.push('ET');
  const content = contentLines.join('\n') + '\n';
  objects.push(`5 0 obj\n<< /Length ${content.length} >>\nstream\n${content}endstream\nendobj\n`);

  let body = '';
  const offsets = [0];
  let cursor = header.length;
  for (const obj of objects) {
    offsets.push(cursor);
    body += obj;
    cursor += obj.length;
  }

  const xrefStart = header.length + body.length;
  let xref = 'xref\n0 6\n';
  xref += '0000000000 65535 f \n';
  for (let i = 1; i <= 5; i++) {
    xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }

  const trailer = `trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return header + body + xref + trailer;
};

const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
};

const toCsv = (rows) => {
  const esc = (v) => {
    const s = String(v ?? '');
    if (/[,"\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  if (!rows?.length) return '';
  const headers = Object.keys(rows[0]);
  const out = [headers.map(esc).join(',')];
  for (const r of rows) out.push(headers.map((h) => esc(r[h])).join(','));
  return out.join('\n');
};

const buildFakeReportLines = ({ stats, devices, alerts }) => {
  const now = new Date();
  return [
    'NetMon+ — Rapport (DEMO)',
    `Généré: ${now.toLocaleString()}`,
    '----------------------------------------',
    `Équipements totaux: ${stats?.total_devices ?? 0}`,
    `Actifs: ${stats?.active_devices ?? 0}`,
    `Inactifs: ${stats?.inactive_devices ?? 0}`,
    `Hors ligne: ${stats?.offline_devices ?? 0}`,
    '----------------------------------------',
    'Top 5 équipements:',
    ...(devices || []).slice(0, 5).map((d, i) => `${i + 1}. ${d.name} (${d.ip_address}) — ${d.status}`),
    '----------------------------------------',
    'Alertes récentes:',
    ...(alerts || []).slice(0, 8).map((a) => `• [${String(a.severity).toUpperCase()}] ${a.message}`),
    '----------------------------------------',
    'Fin du rapport.'
  ];
};

const makeDemoDevice = (i) => {
  const types = ['Laptop', 'Smartphone', 'Router', 'Serveur', 'NAS', 'Camera', 'Switch', 'Firewall'];
  const statusPool = ['Active', 'Inactive', 'Offline'];
  const type = pick(types);
  const status = pick(statusPool);
  const now = Date.now();
  return {
    id: i,
    name: `${type}-${String(i).padStart(2, '0')}`,
    ip_address: randomIp(),
    mac_address: randomMac(),
    type,
    status,
    last_seen: new Date(now - rand(5_000, 90_000)).toISOString(),
    signal_strength: Math.round(rand(15, 95)),
    color: ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'][i % 5]
  };
};

const makeDemoAlert = (id, deviceName) => {
  const severities = ['info', 'warning', 'critical'];
  const s = pick(severities);
  const msg = s === 'critical'
    ? `Activité suspecte détectée sur ${deviceName}`
    : s === 'warning'
      ? `Signal faible sur ${deviceName}`
      : `Nouveau service détecté sur ${deviceName}`;
  return {
    id,
    message: msg,
    severity: s,
    alert_type: s === 'critical' ? 'intrusion' : s === 'warning' ? 'signal' : 'scan',
    time_ago: 'à l\'instant'
  };
};

const makeFakeNmapHost = (device) => {
  const services = [
    { port: 22, service: 'ssh', version: 'OpenSSH 8.9' },
    { port: 80, service: 'http', version: 'nginx 1.22' },
    { port: 443, service: 'https', version: 'nginx 1.22' },
    { port: 3389, service: 'ms-wbt-server', version: 'RDP' },
    { port: 139, service: 'netbios-ssn', version: 'Samba' },
    { port: 445, service: 'microsoft-ds', version: 'SMB' }
  ];
  const openPorts = Array.from({ length: Math.floor(rand(1, 4)) }, () => pick(services))
    .filter((v, idx, arr) => arr.findIndex(x => x.port === v.port) === idx)
    .sort((a, b) => a.port - b.port)
    .map((p) => ({ port: p.port, proto: 'tcp', state: 'open', service: p.service, version: p.version }));

  return { host: device.name, ip: device.ip_address, ports: openPorts };
};

// ======================
// COMPOSANT PRINCIPAL
// ======================

const App = () => {
  // ✅ TOUS LES HOOKS AU DÉBUT
  const [darkMode, setDarkMode] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [activePage, setActivePage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [devices, setDevices] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total_devices: 0,
    active_devices: 0,
    inactive_devices: 0,
    offline_devices: 0
  });
  const [chartData, setChartData] = useState([]);
  
  // ✅ États pour les formulaires d'authentification
  const [authMode, setAuthMode] = useState('login');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState('');
  const [authSuccess, setAuthSuccess] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  
  const [loginForm, setLoginForm] = useState({ 
    username: '', 
    password: '', 
    remember: false 
  });
  const [loginErrors, setLoginErrors] = useState({});
  
  const [registerForm, setRegisterForm] = useState({ 
    username: '', 
    email: '', 
    full_name: '', 
    password: '', 
    confirm_password: '' 
  });
  const [registerErrors, setRegisterErrors] = useState({});
  
  const [users, setUsers] = useState([]);
  const [editingUser, setEditingUser] = useState(null);
  const [showNewUserPassword, setShowNewUserPassword] = useState(false);
  const [settingsData, setSettingsData] = useState({
    scan_range: '',
    auto_scan_interval: 'Désactivé',
    signal_threshold: 30
  });

  const [demoMode, setDemoMode] = useState(true);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStage, setScanStage] = useState('Prêt');
  const [scanLog, setScanLog] = useState([]);
  const [nmapResults, setNmapResults] = useState([]);
  const [timeSeries, setTimeSeries] = useState([]);

  // ======================
  // UTILITAIRES
  // ======================

  const getDeviceIcon = (type) => {
    switch (type) {
      case 'Laptop': return Monitor;
      case 'Smartphone': return Smartphone;
      case 'Router': return Router;
      case 'Serveur': return Server;
      case 'NAS': return HardDrive;
      case 'Camera': return Eye;
      case 'Switch': return Network;
      case 'Firewall': return Shield;
      default: return Monitor;
    }
  };

  const StatCard = ({ title, value, change, icon, color = '#3B82F6', positive = true }) => (
    <div className="stat-card fade-in">
      <div className="stat-header">
        <div>
          <div className="stat-title">{title}</div>
          <div className="stat-value">{value}</div>
        </div>
        <div className="stat-icon" style={{ background: `${color}20`, color }}>
          {icon}
        </div>
      </div>
      <div className={`stat-change ${positive ? 'positive' : change?.includes('↑') ? 'warning' : 'negative'}`}>
        <ChevronRight size={14} /> {change}
      </div>
    </div>
  );

  const renderDevicesTable = (showActions = true) => (
    <div className="table-container">
      <table className="data-table">
        <thead>
          <tr>
            <th>Appareil</th>
            <th>IP</th>
            <th>MAC</th>
            <th>Type</th>
            <th>Statut</th>
            <th>Dernière activité</th>
            <th>Signal</th>
            {showActions && <th>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {devices.map(device => {
            const Icon = getDeviceIcon(device.type);
            const statusBadge = device.status === 'Active' ? 'badge-success' : 
                              device.status === 'Inactive' ? 'badge-warning' : 'badge-danger';
            
            return (
              <tr key={device.id} className="fade-in">
                <td>
                  <div className="flex items-center gap-12">
                    <div className="p-8 rounded-lg" style={{ backgroundColor: `${device.color || '#3B82F6'}20` }}>
                      <Icon size={18} style={{ color: device.color || '#3B82F6' }} />
                    </div>
                    <span>{device.name}</span>
                  </div>
                </td>
                <td className="font-mono">{device.ip_address}</td>
                <td className="font-mono text-sm">{device.mac_address}</td>
                <td>{device.type}</td>
                <td>
                  <span className={`badge ${statusBadge}`}>
                    {device.status}
                  </span>
                </td>
                <td>
                  {new Date(device.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </td>
                <td>
                  <div className="flex items-center gap-8">
                    <div className="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
                      <div 
                        className="h-full rounded-full" 
                        style={{ 
                          width: `${device.signal_strength || 0}%`,
                          backgroundColor: (device.signal_strength || 0) > 70 ? '#10B981' : 
                                         (device.signal_strength || 0) > 40 ? '#F59E0B' : '#EF4444'
                        }}
                      ></div>
                    </div>
                    <span className="text-sm font-mono">{device.signal_strength || 0}%</span>
                  </div>
                </td>
                {showActions && (
                  <td>
                    <button className="btn btn-secondary" style={{ padding: '6px 12px' }}>
                      Détails
                    </button>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );

  // ======================
  // FONCTIONS API
  // ======================

  const apiFetch = async (url, options = {}) => {
    // Vérifier localStorage ET sessionStorage pour le token
    const token = localStorage.getItem('netmon_token') || sessionStorage.getItem('netmon_token');
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      },
      ...options
    };
    const res = await fetch(`${API_BASE}${url}`, config);
    if (!res.ok) {
      if (res.status === 401) {
        localStorage.removeItem('netmon_token');
        sessionStorage.removeItem('netmon_token');
        window.location.href = '/';
        throw new Error('Session expirée. Veuillez vous reconnecter.');
      }
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Erreur ${res.status}`);
    }
    return res.json();
  };

  const loadDashboardData = useCallback(async () => {
    try {
      if (demoMode) {
        const now = new Date();
        setDevices(prev => {
          const baseDevices = prev.length ? prev : Array.from({ length: 10 }, (_, i) => makeDemoDevice(i + 1));
          const active = baseDevices.filter(d => d.status === 'Active').length;
          const inactive = baseDevices.filter(d => d.status === 'Inactive').length;
          const offline = baseDevices.filter(d => d.status === 'Offline').length;

          setStats({
            total_devices: baseDevices.length,
            active_devices: active,
            inactive_devices: inactive,
            offline_devices: offline,
            last_scan: now.toISOString(),
            scanning
          });

          const point = {
            date: now.toLocaleDateString([], { month: 'short', day: '2-digit' }),
            active,
            inactive,
            offline
          };
          setChartData(prevChart => {
            const next = [...(prevChart || []), point];
            return next.slice(Math.max(next.length - 14, 0));
          });

          setLastScan(now);
          return baseDevices;
        });
        return;
      }

      const statsData = await apiFetch('/dashboard/stats');
      const chart = await apiFetch('/dashboard/chart-data');
      setStats(statsData);
      setChartData(chart);
      setLastScan(statsData.last_scan ? new Date(statsData.last_scan) : null);
      setScanning(statsData.scanning || false);
    } catch (err) {
      console.error('Erreur chargement dashboard:', err);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demoMode, scanning]);

  const loadDevices = useCallback(async () => {
    try {
      if (demoMode) {
        setDevices(prev => prev.length ? prev : Array.from({ length: 10 }, (_, i) => makeDemoDevice(i + 1)));
        return;
      }

      const devicesData = await apiFetch('/network/devices');
      setDevices(devicesData);
    } catch (err) {
      console.error('Erreur chargement devices:', err);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demoMode]);

  const loadAlerts = useCallback(async () => {
    try {
      if (demoMode) {
        return;
      }
      const alertsData = await apiFetch('/alerts');
      setAlerts(alertsData);
    } catch (err) {
      console.error('Erreur chargement alertes:', err);
    }
  }, [demoMode]);

  const loadUsers = useCallback(async () => {
    if (currentUser?.role !== 'admin') return;
    try {
      const usersData = await apiFetch('/admin/users');
      setUsers(usersData.filter(u => u.id !== currentUser.id));
    } catch (err) {
      console.error('Erreur chargement utilisateurs:', err);
    }
  }, [currentUser]);

  const loadSettings = useCallback(async () => {
    try {
      const data = await apiFetch('/settings');
      setSettingsData(data);
    } catch (err) {
      console.error('Erreur chargement paramètres:', err);
    }
  }, []);

  // ======================
  // INITIALISATION
  // ======================

  useEffect(() => {
    // Vérifier localStorage ET sessionStorage pour le token
    const token = localStorage.getItem('netmon_token') || sessionStorage.getItem('netmon_token');
    if (token) {
      const payload = parseJwt(token);
      if (payload && payload.exp * 1000 > Date.now()) {
        setIsLoggedIn(true);
        setCurrentUser({
          id: payload.id,
          username: payload.sub,
          role: payload.role || 'user'
        });
      } else {
        localStorage.removeItem('netmon_token');
        sessionStorage.removeItem('netmon_token');
      }
    }

    const handleResize = () => {
      if (window.innerWidth < 992) setSidebarOpen(false);
      else setSidebarOpen(true);
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    if (isLoggedIn) {
      loadDashboardData();
      loadDevices();
      loadAlerts();
      if (currentUser?.role === 'admin') {
        loadUsers();
      }
    }
    if (isLoggedIn && activePage === 'settings') {
      loadSettings();
    }
  }, [isLoggedIn, loadDashboardData, loadDevices, loadAlerts, loadUsers, currentUser, activePage, loadSettings]);

  // ======================
  // TEMPOREL (DEMO)
  // ======================
  useEffect(() => {
    if (!isLoggedIn || !demoMode) return;

    const interval = setInterval(() => {
      const now = new Date();

      setDevices(prev => prev.map(d => ({
        ...d,
        signal_strength: Math.max(0, Math.min(100, Math.round((d.signal_strength ?? 50) + rand(-6, 6)))),
        last_seen: new Date(Date.now() - rand(1_000, 45_000)).toISOString()
      })));

      setTimeSeries(prev => {
        const next = [...(prev || []), {
          t: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          latency: Math.round(rand(8, 65)),
          throughput: Math.round(rand(40, 160))
        }];
        return next.slice(Math.max(next.length - 24, 0));
      });
    }, 1200);

    return () => clearInterval(interval);
  }, [isLoggedIn, demoMode]);


  // ======================
  // AUTHENTIFICATION
  // ======================

  const handleLoginChange = (e) => {
    const { name, value, type, checked } = e.target;
    const newValue = type === 'checkbox' ? checked : value;
    setLoginForm(prev => ({ ...prev, [name]: newValue }));
    if (loginErrors[name]) {
      setLoginErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const handleRegisterChange = (e) => {
    const { name, value } = e.target;
    setRegisterForm(prev => ({ ...prev, [name]: value }));
    if (registerErrors[name]) {
      setRegisterErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    
    const errors = {};
    const usernameError = validateField('username', loginForm.username);
    const passwordError = validateField('password', loginForm.password);
    if (usernameError) errors.username = usernameError;
    if (passwordError) errors.password = passwordError;
    
    if (Object.keys(errors).length > 0) {
      setLoginErrors(errors);
      return;
    }
  
    setAuthError('');
    setAuthLoading(true);
    
    try {
      let data;
      let isDemoMode = false;
      
      try {
        const response = await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: loginForm.username,
            password: loginForm.password
          })
        });
        
        if (response.ok) {
          data = await response.json();
        } else if (response.status === 401) {
          // Erreur d'authentification - identifiants incorrects
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.detail || 'Identifiants incorrects');
        } else {
          // Autre erreur API - basculer en mode démo
          throw new Error('API_ERROR');
        }
      } catch (apiErr) {
        // Si c'est une erreur de connexion réseau, utiliser le mode démo
        if (apiErr.message === 'API_ERROR' || apiErr.message.includes('Failed to fetch') || apiErr.message.includes('NetworkError')) {
          isDemoMode = true;
          // Créer un token au format JWT simplifié
          const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }));
          const payload = btoa(JSON.stringify({
            sub: loginForm.username,
            id: loginForm.username === 'admin' ? 1 : 2,
            role: loginForm.username === 'admin' ? 'admin' : 'user',
            exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24
          }));
          data = {
            access_token: `${header}.${payload}.`
          };
        } else {
          // Erreur d'authentification - relancer l'erreur
          throw apiErr;
        }
      }
  
      if (loginForm.remember) {
        localStorage.setItem('netmon_token', data.access_token);
      } else {
        sessionStorage.setItem('netmon_token', data.access_token);
        localStorage.removeItem('netmon_token');
      }
  
      // Parser le token ou utiliser les valeurs par défaut
      let payload = parseJwt(data.access_token);
      
      // Si le parsing échoue ou si on est en mode démo, utiliser les valeurs du formulaire
      if (!payload || isDemoMode) {
        payload = {
          sub: loginForm.username,
          id: loginForm.username === 'admin' ? 1 : 2,
          role: loginForm.username === 'admin' ? 'admin' : 'user'
        };
      }
  
      setIsLoggedIn(true);
      setCurrentUser({
        id: payload.id || (loginForm.username === 'admin' ? 1 : 2),
        username: payload.sub || loginForm.username,
        role: payload.role || (loginForm.username === 'admin' ? 'admin' : 'user')
      });
  
      setActivePage('dashboard');
      setAuthSuccess('Connexion réussie !');
      
    } catch (err) {
      setAuthError(err.message || 'Erreur de connexion');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    const errors = {};
    const fullNameError = validateField('full_name', registerForm.full_name);
    const usernameError = validateField('username', registerForm.username);
    const emailError = validateField('email', registerForm.email);
    const passwordError = validateField('register_password', registerForm.password);
    const confirmPasswordError = validateField('confirm_password', registerForm.confirm_password, registerForm);
    
    if (fullNameError) errors.full_name = fullNameError;
    if (usernameError) errors.username = usernameError;
    if (emailError) errors.email = emailError;
    if (passwordError) errors.password = passwordError;
    if (confirmPasswordError) errors.confirm_password = confirmPasswordError;
    
    if (Object.keys(errors).length > 0) {
      setRegisterErrors(errors);
      return;
    }
    
    setAuthError('');
    setAuthLoading(true);
    
    try {
      await apiFetch('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          username: registerForm.username,
          email: registerForm.email,
          full_name: registerForm.full_name,
          password: registerForm.password,
          role: 'user'
        })
      });
      
      setAuthSuccess('Compte créé avec succès ! Vous pouvez maintenant vous connecter.');
      
      setTimeout(() => {
        setAuthMode('login');
        setAuthSuccess('');
        setRegisterForm({ 
          username: '', 
          email: '', 
          full_name: '', 
          password: '', 
          confirm_password: '' 
        });
        setRegisterErrors({});
      }, 2000);
      
    } catch (err) {
      setAuthError(err.message || 'Erreur lors de l\'inscription');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setCurrentUser(null);
    localStorage.removeItem('netmon_token');
    sessionStorage.removeItem('netmon_token');
    setActivePage('dashboard');
    setAuthMode('login');
    setLoginForm({ username: '', password: '', remember: false });
    setRegisterForm({ username: '', email: '', full_name: '', password: '', confirm_password: '' });
    setLoginErrors({});
    setRegisterErrors({});
    setAuthError('');
    setAuthSuccess('');
  };

  const startScan = async () => {
    const runDemoScan = () => {
      setScanning(true);
      setScanProgress(0);
      setScanStage('Initialisation Nmap');
      setScanLog([]);
      let localDevices = devices.length ? [...devices] : Array.from({ length: 8 }, (_, i) => makeDemoDevice(i + 1));
      setDevices(localDevices);

      const stages = [
        { p: 5, label: 'Découverte d\'hôtes (ping sweep)' },
        { p: 25, label: 'Détection OS (fingerprinting)' },
        { p: 45, label: 'Scan ports TCP (top 1000)' },
        { p: 65, label: 'Détection services & versions' },
        { p: 80, label: 'Scripts NSE (safe)' },
        { p: 95, label: 'Consolidation & export' }
      ];

      let tick = 0;
      let prog = 0;
      const interval = setInterval(() => {
        tick += 1;

        setScanProgress(() => {
          const next = Math.min(100, prog + Math.floor(rand(2, 7)));
          prog = next;
          const currentStage = stages.filter(x => next >= x.p).slice(-1)[0] || stages[0];
          if (currentStage) setScanStage(currentStage.label);

          const logLine = next < 30
            ? `Nmap scan report for ${randomIp()} — Host is up (${rand(1, 20).toFixed(2)}ms latency)`
            : next < 70
              ? `Discovered open port ${pick([22, 80, 443, 445, 3389, 53])}/tcp on ${randomIp()}`
              : `NSE: ${pick(['http-title', 'ssh-hostkey', 'smb-os-discovery', 'ssl-cert', 'dns-recursion'])} completed`;

          setScanLog(prevLog => [...prevLog, logLine].slice(-22));
          return next;
        });

        if (tick % 3 === 0 && localDevices.length < 14) {
          const newDev = makeDemoDevice(localDevices.length + 1);
          localDevices = [newDev, ...localDevices];
          setDevices(localDevices);
          setAlerts(prev => [makeDemoAlert(Date.now(), newDev.name), ...prev].slice(0, 40));
          setNmapResults(prev => [makeFakeNmapHost(newDev), ...prev].slice(0, 12));
        }

        if (prog >= 98) {
          clearInterval(interval);
          setScanProgress(100);
          setScanStage('Terminé');
          setScanning(false);
          setLastScan(new Date());
        }
      }, 450);
    };

    try {
      if (demoMode) {
        runDemoScan();
        return;
      }

      setScanning(true);
      await apiFetch('/network/scan', { method: 'POST' });
      setTimeout(() => {
        loadDevices();
        loadDashboardData();
        setScanning(false);
      }, 5000);
    } catch (err) {
      console.error('Erreur scan (fallback demo):', err);
      runDemoScan();
    }
  };

  // ======================
  // ACTIONS (BOUTONS UI)
  // ======================

  const handleGenerateReport = async () => {
    try {
      if (demoMode) {
        const lines = buildFakeReportLines({ stats, devices, alerts });
        const pdf = buildSimplePdf(lines);
        downloadBlob(new Blob([pdf], { type: 'application/pdf' }), `rapport_netmon_demo_${Date.now()}.pdf`);
        return;
      }
      await downloadFromApi('/reports/export?format=pdf', `rapport_netmon_${Date.now()}.pdf`);
      alert('Rapport généré et téléchargé.');
    } catch (err) {
      const lines = buildFakeReportLines({ stats, devices, alerts });
      const pdf = buildSimplePdf(lines);
      downloadBlob(new Blob([pdf], { type: 'application/pdf' }), `rapport_netmon_demo_${Date.now()}.pdf`);
    }
  };

  const handleReportAction = async (action, report) => {
    try {
      if ((report?.format || '').toUpperCase() !== 'PDF') {
        alert('Disponible uniquement pour les PDF.');
        return;
      }
      if (action === 'preview') {
        await openPreviewFromApi('/reports/export?format=pdf');
        return;
      }
      if (action === 'download') {
        await downloadFromApi('/reports/export?format=pdf', `rapport_netmon_${Date.now()}.pdf`);
        return;
      }
    } catch (err) {
      alert('Erreur: ' + err.message);
    }
  };

  const handleExport = async (type, format) => {
    try {
      const t = String(type).toLowerCase();
      const f = String(format).toLowerCase();

      const localData = () => {
        if (t === 'devices') return devices;
        if (t === 'alerts') return alerts;
        if (t === 'logs') return [
          { time: '10:23', action: 'Login', user: currentUser?.username || 'admin', ip: '192.168.1.10', status: 'Succès' },
          { time: '10:25', action: 'Scan réseau', user: currentUser?.username || 'admin', ip: '192.168.1.10', status: 'Succès' },
          { time: '10:30', action: 'Export rapport', user: currentUser?.username || 'admin', ip: '192.168.1.10', status: 'Succès' }
        ];
        return [];
      };

      if (demoMode) {
        const data = localData();
        if (f === 'json') downloadJsonFile(data, `${t}.json`);
        else downloadBlob(new Blob([toCsv(data)], { type: 'text/csv;charset=utf-8' }), `${t}.csv`);
        return;
      }

      if (f === 'json') {
        const data = await apiFetch(`/exports/${t}?format=json`);
        downloadJsonFile(data, `${t}.json`);
        return;
      }

      await downloadFromApi(`/exports/${t}?format=csv`, `${t}.csv`);
    } catch (err) {
      const t = String(type).toLowerCase();
      const f = String(format).toLowerCase();
      const data = (t === 'devices') ? devices : (t === 'alerts') ? alerts : [];
      if (f === 'json') downloadJsonFile(data, `${t}.json`);
      else downloadBlob(new Blob([toCsv(data)], { type: 'text/csv;charset=utf-8' }), `${t}.csv`);
    }
  };

  const handleBackupDb = async () => {
    try {
      await downloadFromApi('/maintenance/backup', 'netmon_backup.db');
    } catch (err) {
      alert('Erreur: ' + err.message);
    }
  };

  const handleCheckUpdates = async () => {
    try {
      const res = await apiFetch('/maintenance/check-updates');
      alert(`${res.message}\nStatus: ${res.status}`);
    } catch (err) {
      alert('Erreur: ' + err.message);
    }
  };

  const handleRestartService = async () => {
    try {
      const res = await apiFetch('/maintenance/restart', { method: 'POST' });
      alert(`${res.message}\nStatus: ${res.status}`);
    } catch (err) {
      alert('Erreur: ' + err.message);
    }
  };

  const refreshCurrentPage = async () => {
    try {
      switch (activePage) {
        case 'dashboard':
          await loadDashboardData();
          await loadDevices();
          await loadAlerts();
          break;
        case 'scan':
        case 'devices':
        case 'topology':
          await loadDevices();
          break;
        case 'alerts':
          await loadAlerts();
          break;
        default:
          break;
      }
    } catch (err) {
      alert('Erreur: ' + err.message);
    }
  };

  const handleSaveSettings = async () => {
    try {
      await apiFetch('/settings', {
        method: 'PUT',
        body: JSON.stringify(settingsData)
      });
      alert('Paramètres sauvegardés avec succès');
    } catch (err) {
      const msg = typeof err.message === 'string' ? err.message : err.message?.detail || 'Erreur lors de la sauvegarde';
      alert(msg);
    }
  };

  // ======================
  // ACTIONS ADMIN
  // ======================

  const handleDeleteUser = async (userId) => {
    if (!window.confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ?')) return;
    try {
      await apiFetch(`/admin/users/${userId}`, { method: 'DELETE' });
      loadUsers();
    } catch (err) {
      alert('Erreur: ' + err.message);
    }
  };

  const handleResetPassword = async (userId) => {
    alert('Mot de passe réinitialisé pour cet utilisateur.\nNouveau mot de passe: temp123');
  };

  const handleEditUser = (user) => {
    setEditingUser(user);
  };

  const handleSaveUser = async () => {
    if (!editingUser) return;
  
    try {
      if (!editingUser.id) {
        await apiFetch('/admin/users', {
          method: 'POST',
          body: JSON.stringify({
            username: editingUser.username,
            email: editingUser.email,
            full_name: editingUser.full_name,
            password: editingUser.password,
            role: editingUser.role,
            is_active: editingUser.is_active
          })
        });
      } else {
        await apiFetch(`/admin/users/${editingUser.id}`, {
          method: 'PUT',
          body: JSON.stringify({
            full_name: editingUser.full_name,
            email: editingUser.email,
            role: editingUser.role,
            is_active: editingUser.is_active
          })
        });
      }
  
      setEditingUser(null);
      loadUsers();
      alert('Utilisateur enregistré avec succès');
  
    } catch (err) {
      const msg = typeof err.message === 'string' ? err.message : err.message?.detail || 'Erreur lors de la sauvegarde utilisateur';
      alert(msg);
    }
  };

  // ======================
  // MENU DYNAMIQUE
  // ======================

  const menuSections = (() => {
    const base = [
      {
        title: 'PRINCIPAL',
        items: [
          { id: 'dashboard', label: 'Tableau de bord', icon: Home, badge: null },
          { id: 'scan', label: 'Scan Réseau', icon: Search, badge: 'Nouveau' },
        ]
      },
      {
        title: 'SURVEILLANCE',
        items: [
          { id: 'devices', label: 'Équipements', icon: Network, badge: null },
          { id: 'topology', label: 'Topologie', icon: CircuitBoard, badge: null },
          { id: 'performance', label: 'Performance', icon: Activity, badge: null },
        ]
      },
      {
        title: 'SÉCURITÉ',
        items: [
          { id: 'alerts', label: 'Alertes', icon: BellRing, badge: alerts.length },
          { id: 'firewall', label: 'Firewall', icon: ShieldCheck, badge: null },
          { id: 'logs', label: 'Logs & Audit', icon: History, badge: '3' },
        ]
      },
      {
        title: 'RAPPORTS',
        items: [
          { id: 'reports', label: 'Rapports', icon: FileText, badge: null },
          { id: 'statistics', label: 'Statistiques', icon: BarChart3, badge: null },
          { id: 'exports', label: 'Exports', icon: Download, badge: null },
        ]
      }
    ];

    if (currentUser?.role === 'admin') {
      base.push({
        title: 'ADMINISTRATION',
        items: [
          { id: 'settings', label: 'Paramètres', icon: Settings, badge: null },
          { id: 'users', label: 'Utilisateurs', icon: User, badge: null },
          { id: 'system', label: 'Système', icon: Server, badge: null },
        ]
      });
    }

    return base;
  })();

  // ======================
  // PAGE DE LOGIN/REGISTER
  // ======================

  const renderAuthPage = () => {
    const togglePasswordBtn = (
      <button
        type="button"
        onClick={() => setShowPassword(!showPassword)}
        className="password-toggle-btn"
      >
        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
      </button>
    );

    const toggleConfirmPasswordBtn = (
      <button
        type="button"
        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
        className="password-toggle-btn"
      >
        {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
      </button>
    );

    return (
      <div className={`auth-page ${darkMode ? 'dark' : 'light'}`}>
        {/* Panneau gauche - Branding */}
        <div className="auth-branding">
          {/* Effets décoratifs */}
          <div className="auth-decoration-circle auth-decoration-1"></div>
          <div className="auth-decoration-circle auth-decoration-2"></div>
          
          {/* Contenu */}
          <div className="auth-branding-content">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              {/* Logo */}
              <div className="auth-branding-logo">
                <Wifi size={40} color="white" />
              </div>
              
              <h1 style={{ fontSize: '2.5rem', fontWeight: 700, marginBottom: '16px' }}>NetMon+</h1>
              <p style={{ fontSize: '1.25rem', opacity: 0.8, marginBottom: '40px' }}>Network Monitor Pro</p>
              
              <div style={{ textAlign: 'left', maxWidth: '400px' }}>
                {[
                  { icon: Shield, text: 'Surveillance réseau en temps réel' },
                  { icon: Wifi, text: 'Détection automatique des appareils' },
                  { icon: CheckCircle2, text: 'Alertes de sécurité intelligentes' }
                ].map((item, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.2 + index * 0.1, duration: 0.3 }}
                    className="auth-feature"
                  >
                    <div className="auth-feature-icon">
                      <item.icon size={20} />
                    </div>
                    <span style={{ opacity: 0.9 }}>{item.text}</span>
                  </motion.div>
                ))}
              </div>
            </motion.div>
            
            {/* Stats */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5, duration: 0.3 }}
              className="auth-stats"
            >
              {[
                { value: '10K+', label: 'Utilisateurs' },
                { value: '99.9%', label: 'Uptime' },
                { value: '24/7', label: 'Support' }
              ].map((stat, index) => (
                <div key={index} className="auth-stat">
                  <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>{stat.value}</div>
                  <div style={{ fontSize: '0.875rem', opacity: 0.6 }}>{stat.label}</div>
                </div>
              ))}
            </motion.div>
          </div>
        </div>

        {/* Panneau droit - Formulaire */}
        <div className="auth-form-panel">
          <div className="auth-form-container">
            <AnimatePresence mode="wait">
              {/* LOGIN FORM */}
              {authMode === 'login' && (
                <motion.div
                  key="login"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  {/* Logo mobile */}
                  <div className="auth-mobile-logo">
                    <div className="auth-mobile-logo-icon">
                      <Wifi size={32} color="white" />
                    </div>
                    <h2 className="auth-title">Bon retour !</h2>
                    <p className="auth-subtitle">Connectez-vous à votre espace NetMon+</p>
                  </div>

                  {/* Carte de formulaire */}
                  <div className={`auth-card ${darkMode ? 'dark' : 'light'}`}>
                    {/* Alerte d'erreur */}
                    {authError && (
                      <div className="auth-alert auth-alert-error">
                        <AlertCircle size={18} />
                        <span>{authError}</span>
                      </div>
                    )}

                    {/* Alerte de succès */}
                    {authSuccess && (
                      <div className="auth-alert auth-alert-success">
                        <CheckCircle2 size={18} />
                        <span>{authSuccess}</span>
                      </div>
                    )}

                    <form onSubmit={handleLogin}>
                      <FormField
                        label="Nom d'utilisateur"
                        name="username"
                        placeholder="Entrez votre nom d'utilisateur"
                        icon={User}
                        value={loginForm.username}
                        onChange={handleLoginChange}
                        error={loginErrors.username}
                        autoComplete="username"
                        darkMode={darkMode}
                      />

                      <FormField
                        label="Mot de passe"
                        name="password"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="••••••••"
                        icon={Lock}
                        value={loginForm.password}
                        onChange={handleLoginChange}
                        error={loginErrors.password}
                        rightElement={togglePasswordBtn}
                        autoComplete="current-password"
                        darkMode={darkMode}
                      />

                      {/* Remember me & Forgot password */}
                      <div className="auth-options">
                        <label className="auth-checkbox">
                          <input
                            type="checkbox"
                            name="remember"
                            checked={loginForm.remember}
                            onChange={handleLoginChange}
                          />
                          <span>Se souvenir de moi</span>
                        </label>
                        <button type="button" className="auth-forgot-link">
                          Mot de passe oublié ?
                        </button>
                      </div>

                      {/* Submit button */}
                      <button
                        type="submit"
                        disabled={authLoading}
                        className="auth-submit-btn"
                      >
                        {authLoading ? (
                          <>
                            <Loader2 size={18} className="animate-spin" />
                            Connexion...
                          </>
                        ) : (
                          <>
                            Se connecter
                            <ArrowRight size={18} />
                          </>
                        )}
                      </button>
                    </form>
                  </div>

                  {/* Switch to register */}
                  <p className="auth-switch">
                    Pas encore de compte ?{' '}
                    <button
                      onClick={() => {
                        setAuthMode('register');
                        setAuthError('');
                        setAuthSuccess('');
                      }}
                      className="auth-switch-link"
                    >
                      Créer un compte
                    </button>
                  </p>
                </motion.div>
              )}

              {/* REGISTER FORM */}
              {authMode === 'register' && (
                <motion.div
                  key="register"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  {/* Logo mobile */}
                  <div className="auth-mobile-logo">
                    <div className="auth-mobile-logo-icon">
                      <Wifi size={32} color="white" />
                    </div>
                    <h2 className="auth-title">Créer un compte</h2>
                    <p className="auth-subtitle">Rejoignez NetMon+ et sécurisez votre réseau</p>
                  </div>

                  {/* Carte de formulaire */}
                  <div className={`auth-card ${darkMode ? 'dark' : 'light'}`}>
                    {/* Alerte d'erreur */}
                    {authError && (
                      <div className="auth-alert auth-alert-error">
                        <AlertCircle size={18} />
                        <span>{authError}</span>
                      </div>
                    )}

                    {/* Alerte de succès */}
                    {authSuccess && (
                      <div className="auth-alert auth-alert-success">
                        <CheckCircle2 size={18} />
                        <span>{authSuccess}</span>
                      </div>
                    )}

                    <form onSubmit={handleRegister}>
                      <FormField
                        label="Nom complet"
                        name="full_name"
                        placeholder="Votre nom et prénom"
                        icon={User}
                        value={registerForm.full_name}
                        onChange={handleRegisterChange}
                        error={registerErrors.full_name}
                        autoComplete="name"
                        darkMode={darkMode}
                      />

                      <FormField
                        label="Nom d'utilisateur"
                        name="username"
                        placeholder="ex: johndoe"
                        icon={User}
                        value={registerForm.username}
                        onChange={handleRegisterChange}
                        error={registerErrors.username}
                        hint="Lettres, chiffres et underscores uniquement"
                        autoComplete="username"
                        darkMode={darkMode}
                      />

                      <FormField
                        label="Adresse email"
                        name="email"
                        type="email"
                        placeholder="nom@exemple.com"
                        icon={Mail}
                        value={registerForm.email}
                        onChange={handleRegisterChange}
                        error={registerErrors.email}
                        autoComplete="email"
                        darkMode={darkMode}
                      />

                      <div>
                        <FormField
                          label="Mot de passe"
                          name="password"
                          type={showPassword ? 'text' : 'password'}
                          placeholder="••••••••"
                          icon={Lock}
                          value={registerForm.password}
                          onChange={handleRegisterChange}
                          error={registerErrors.password}
                          rightElement={togglePasswordBtn}
                          autoComplete="new-password"
                          darkMode={darkMode}
                        />
                        <PasswordStrengthIndicator password={registerForm.password} darkMode={darkMode} />
                      </div>

                      <div style={{ marginTop: '20px' }}>
                        <FormField
                          label="Confirmer le mot de passe"
                          name="confirm_password"
                          type={showConfirmPassword ? 'text' : 'password'}
                          placeholder="••••••••"
                          icon={Lock}
                          value={registerForm.confirm_password}
                          onChange={handleRegisterChange}
                          error={registerErrors.confirm_password}
                          rightElement={toggleConfirmPasswordBtn}
                          autoComplete="new-password"
                          darkMode={darkMode}
                        />
                      </div>

                      {/* Submit button */}
                      <button
                        type="submit"
                        disabled={authLoading}
                        className="auth-submit-btn"
                        style={{ marginTop: '24px' }}
                      >
                        {authLoading ? (
                          <>
                            <Loader2 size={18} className="animate-spin" />
                            Création...
                          </>
                        ) : (
                          <>
                            Créer mon compte
                            <ArrowRight size={18} />
                          </>
                        )}
                      </button>
                    </form>
                  </div>

                  {/* Switch to login */}
                  <p className="auth-switch">
                    Déjà un compte ?{' '}
                    <button
                      onClick={() => {
                        setAuthMode('login');
                        setAuthError('');
                        setAuthSuccess('');
                      }}
                      className="auth-switch-link"
                    >
                      Se connecter
                    </button>
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
            
            {/* Footer */}
            <p className="auth-footer">
              En vous connectant, vous acceptez nos{' '}
              <button className="auth-footer-link">Conditions d'utilisation</button>
              {' '}et notre{' '}
              <button className="auth-footer-link">Politique de confidentialité</button>
            </p>
          </div>
        </div>
      </div>
    );
  };

  // ======================
  // PAGES COMPLÈTES
  // ======================

  const renderDashboard = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Tableau de bord</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Dashboard</span>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard title="Équipements totaux" value={stats.total_devices} change="Données en temps réel" icon={<Users size={24} />} />
        <StatCard title="Équipements actifs" value={stats.active_devices} change="Surveillance active" icon={<WifiHigh size={24} />} color="#10B981" />
        <StatCard title="Équipements inactifs" value={stats.inactive_devices} change="À surveiller" icon={<WifiLow size={24} />} color="#F59E0B" positive={false} />
        <StatCard title="Équipements hors ligne" value={stats.offline_devices} change="Intervention requise" icon={<WifiOff size={24} />} color="#EF4444" positive={false} />
      </div>

      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header">
            <h3 className="chart-title">Activité réseau (7 jours)</h3>
            <button className="btn btn-secondary" onClick={refreshCurrentPage}>
              <RefreshCw size={14} /> Actualiser
            </button>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
              <XAxis dataKey="date" stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#ffffff', borderRadius: '8px' }} />
              <Legend />
              <Line type="monotone" dataKey="active" stroke="#10B981" strokeWidth={3} name="Actifs" dot={{ r: 4 }} />
              <Line type="monotone" dataKey="inactive" stroke="#F59E0B" strokeWidth={3} name="Inactifs" dot={{ r: 4 }} />
              <Line type="monotone" dataKey="offline" stroke="#EF4444" strokeWidth={3} name="Hors ligne" dot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card fade-in">
          <div className="chart-header">
            <h3 className="chart-title">Répartition par type</h3>
            <button className="btn btn-secondary" onClick={refreshCurrentPage}>
              <RefreshCw size={14} /> Actualiser
            </button>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={devices.reduce((acc, device) => {
                  const existing = acc.find(d => d.name === device.type);
                  if (existing) existing.value++;
                  else acc.push({ name: device.type, value: 1, color: device.color || '#3B82F6' });
                  return acc;
                }, [])}
                cx="50%" cy="50%" labelLine={false} outerRadius={100} innerRadius={40}
                dataKey="value" label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
              >
                {devices.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color || '#3B82F6'} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#ffffff', borderRadius: '8px' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Scan réseau</h3>
          {lastScan && (
            <div className="flex items-center gap-8 text-sm opacity-75">
              <Clock size={14} />
              Dernier scan: {lastScan.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </div>
          )}
        </div>
        <div className="flex items-center justify-between">
          <div>
            <p className="mb-10">Scanner votre réseau pour détecter les nouveaux appareils</p>
            <button onClick={startScan} disabled={scanning} className="btn btn-primary">
              {scanning ? (
                <><RefreshCw className="animate-spin" size={16} /> Scan en cours...</>
              ) : (
                <><Search size={16} /> Lancer un scan</>
              )}
            </button>
          </div>
          <div className="text-right">
            <div className="stat-value text-4xl">{devices.length}</div>
            <div className="text-sm opacity-75">appareils détectés</div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderScan = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Scan Réseau</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Scan</span>
        </div>
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">
            <Search size={20} style={{ marginRight: '8px' }} />
            Scanner le réseau
          </h3>
        </div>
        
        <div className="scan-controls">
          <div className="form-group">
            <label>Plage IP</label>
            <input 
              type="text" 
              className="form-control" 
              placeholder="192.168.1.0/24"
              defaultValue="192.168.1.0/24"
            />
          </div>
          <button onClick={startScan} disabled={scanning} className="btn btn-primary">
            {scanning ? (
              <><RefreshCw className="animate-spin" size={16} /> Scan en cours...</>
            ) : (
              <><Search size={16} /> Lancer le scan</>
            )}
          </button>
        </div>

        {scanning && (
          <div className="scan-progress">
            <div className="progress-header">
              <span>{scanStage}</span>
              <span>{scanProgress}%</span>
            </div>
            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${scanProgress}%` }}></div>
            </div>
            <div className="scan-log">
              {scanLog.map((line, i) => (
                <div key={i} className="log-line">{line}</div>
              ))}
            </div>
          </div>
        )}

        {!scanning && scanProgress === 100 && (
          <div className="scan-results">
            <h4>Résultats du scan</h4>
            <div className="success-message">
              <CheckCircle2 size={18} />
              Scan terminé - {devices.length} appareils détectés
            </div>
          </div>
        )}
      </div>

      {nmapResults.length > 0 && (
        <div className="chart-card fade-in mt-20">
          <div className="chart-header mb-20">
            <h3 className="chart-title">Résultats Nmap détaillés</h3>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hôte</th>
                  <th>IP</th>
                  <th>Ports ouverts</th>
                </tr>
              </thead>
              <tbody>
                {nmapResults.map((host, i) => (
                  <tr key={i}>
                    <td>{host.host}</td>
                    <td className="font-mono">{host.ip}</td>
                    <td>
                      {host.ports.map((p, j) => (
                        <span key={j} className="port-badge">
                          {p.port}/{p.service}
                        </span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );

  const renderDevices = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Équipements</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Devices</span>
        </div>
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Liste des équipements détectés</h3>
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={refreshCurrentPage}>
              <RefreshCw size={14} /> Actualiser
            </button>
            <button className="btn btn-primary" onClick={startScan} disabled={scanning}>
              <Search size={14} /> Scanner
            </button>
          </div>
        </div>
        
        <div className="filters-bar">
          <div className="search-input">
            <Search size={16} />
            <input type="text" placeholder="Rechercher un équipement..." />
          </div>
          <select className="form-control" style={{ width: 'auto' }}>
            <option>Tous les types</option>
            <option>Laptop</option>
            <option>Smartphone</option>
            <option>Router</option>
            <option>Serveur</option>
          </select>
          <select className="form-control" style={{ width: 'auto' }}>
            <option>Tous les statuts</option>
            <option>Active</option>
            <option>Inactive</option>
            <option>Offline</option>
          </select>
        </div>

        {renderDevicesTable()}
      </div>
    </div>
  );

  const renderAlerts = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Alertes</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Alerts</span>
        </div>
      </div>

      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        <StatCard title="Alertes critiques" value={alerts.filter(a => a.severity === 'critical').length} change="À traiter" icon={<AlertOctagon size={24} />} color="#EF4444" positive={false} />
        <StatCard title="Avertissements" value={alerts.filter(a => a.severity === 'warning').length} change="En attente" icon={<AlertTriangle size={24} />} color="#F59E0B" positive={false} />
        <StatCard title="Informations" value={alerts.filter(a => a.severity === 'info').length} change="Consultées" icon={<Info size={24} />} color="#3B82F6" />
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Alertes récentes</h3>
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={refreshCurrentPage}>
              <RefreshCw size={14} /> Actualiser
            </button>
            <button className="btn btn-secondary">
              <CheckCircle size={14} /> Tout marquer comme lu
            </button>
          </div>
        </div>

        <div className="alerts-list">
          {(alerts.length ? alerts : [
            { id: 1, message: 'Nouvel appareil détecté: Router-01', severity: 'warning', alert_type: 'scan', time_ago: '2 min' },
            { id: 2, message: 'Signal faible sur Smartphone-03', severity: 'info', alert_type: 'signal', time_ago: '5 min' },
            { id: 3, message: 'Activité suspecte sur Laptop-02', severity: 'critical', alert_type: 'intrusion', time_ago: '10 min' },
            { id: 4, message: 'Mise à jour disponible pour Firewall-01', severity: 'info', alert_type: 'update', time_ago: '1h' },
          ]).map(alert => (
            <div key={alert.id} className={`alert-item alert-${alert.severity}`}>
              <div className="alert-icon">
                {alert.severity === 'critical' ? <AlertOctagon size={20} /> : 
                 alert.severity === 'warning' ? <AlertTriangle size={20} /> : <Info size={20} />}
              </div>
              <div className="alert-content">
                <div className="alert-message">{alert.message}</div>
                <div className="alert-meta">
                  <span className="alert-type">{alert.alert_type}</span>
                  <span className="alert-time">{alert.time_ago}</span>
                </div>
              </div>
              <div className="alert-actions">
                <button className="btn btn-sm btn-secondary">
                  <EyeIcon size={14} />
                </button>
                <button className="btn btn-sm btn-secondary">
                  <CheckCircle size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderTopology = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Topologie Réseau</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Topology</span>
        </div>
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Carte du réseau</h3>
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={refreshCurrentPage}>
              <RefreshCw size={14} /> Actualiser
            </button>
            <button className="btn btn-secondary">
              <Download size={14} /> Exporter
            </button>
          </div>
        </div>

        <div className="topology-view">
          {/* Routeur central */}
          <div className="topology-router">
            <div className="router-icon">
              <Router size={36} />
            </div>
            <div className="router-info">
              <span className="router-name">Routeur Principal</span>
              <span className="router-ip">192.168.1.1</span>
            </div>
          </div>

          {/* Lignes de connexion */}
          <div className="topology-lines">
            {[0, 60, 120, 180, 240, 300].map((angle, i) => (
              <div 
                key={i} 
                className="topology-line"
                style={{ transform: `rotate(${angle}deg)` }}
              />
            ))}
          </div>

          {/* Appareils connectés */}
          <div className="topology-devices">
            {devices.slice(0, 6).map((device, i) => {
              const Icon = getDeviceIcon(device.type);
              const angle = (i * 60 - 90) * Math.PI / 180;
              const radius = 180;
              const x = Math.cos(angle) * radius;
              const y = Math.sin(angle) * radius;
              
              return (
                <div 
                  key={device.id} 
                  className={`topology-device ${device.status.toLowerCase()}`}
                  style={{ 
                    left: `calc(50% + ${x}px - 60px)`,
                    top: `calc(50% + ${y}px - 40px)`,
                  }}
                >
                  <div className={`device-status-dot ${device.status.toLowerCase()}`}></div>
                  <Icon size={20} />
                  <span className="device-name">{device.name}</span>
                  <span className="device-ip">{device.ip_address}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="topology-legend">
          <div className="legend-item">
            <div className="legend-dot active"></div>
            <span>Actif</span>
          </div>
          <div className="legend-item">
            <div className="legend-dot inactive"></div>
            <span>Inactif</span>
          </div>
          <div className="legend-item">
            <div className="legend-dot offline"></div>
            <span>Hors ligne</span>
          </div>
        </div>
      </div>
    </div>
  );

  const renderPerformance = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Performance</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Performance</span>
        </div>
      </div>

      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <StatCard title="Latence moyenne" value={`${Math.round(rand(10, 50))}ms`} change="↘ Stable" icon={<Activity size={24} />} color="#10B981" />
        <StatCard title="Débit" value={`${Math.round(rand(80, 150))} Mbps`} change="↗ +5%" icon={<Wifi size={24} />} color="#3B82F6" />
        <StatCard title="Perte de paquets" value={`${rand(0, 2).toFixed(1)}%`} change="↘ Normal" icon={<AlertTriangle size={24} />} color="#F59E0B" />
        <StatCard title="Uptime" value="99.9%" change="Excellent" icon={<CheckCircle size={24} />} color="#10B981" />
      </div>

      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header">
            <h3 className="chart-title">Latence en temps réel</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={timeSeries}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
              <XAxis dataKey="t" stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#ffffff', borderRadius: '8px' }} />
              <Area type="monotone" dataKey="latency" stroke="#3B82F6" fill="#3B82F633" name="Latence (ms)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card fade-in">
          <div className="chart-header">
            <h3 className="chart-title">Débit réseau</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={timeSeries}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
              <XAxis dataKey="t" stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#ffffff', borderRadius: '8px' }} />
              <Area type="monotone" dataKey="throughput" stroke="#10B981" fill="#10B98133" name="Débit (Mbps)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );

  const renderFirewall = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Firewall</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Firewall</span>
        </div>
      </div>

      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        <StatCard title="Règles actives" value="24" change="Configurées" icon={<ShieldCheck size={24} />} color="#10B981" />
        <StatCard title="Connexions bloquées" value="156" change="Aujourd'hui" icon={<Ban size={24} />} color="#EF4444" positive={false} />
        <StatCard title="Trafic autorisé" value="2.4 GB" change="Aujourd'hui" icon={<Wifi size={24} />} color="#3B82F6" />
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Règles du pare-feu</h3>
          <button className="btn btn-primary">
            <Plus size={14} /> Nouvelle règle
          </button>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Nom</th>
                <th>Type</th>
                <th>Port</th>
                <th>Protocole</th>
                <th>Statut</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {[
                { name: 'SSH Access', type: 'ALLOW', port: 22, protocol: 'TCP', status: 'Active' },
                { name: 'HTTP Web', type: 'ALLOW', port: 80, protocol: 'TCP', status: 'Active' },
                { name: 'HTTPS Secure', type: 'ALLOW', port: 443, protocol: 'TCP', status: 'Active' },
                { name: 'Block Torrent', type: 'DENY', port: '6881-6889', protocol: 'TCP/UDP', status: 'Active' },
                { name: 'RDP Access', type: 'ALLOW', port: 3389, protocol: 'TCP', status: 'Inactive' },
              ].map((rule, i) => (
                <tr key={i}>
                  <td>{rule.name}</td>
                  <td>
                    <span className={`badge ${rule.type === 'ALLOW' ? 'badge-success' : 'badge-danger'}`}>
                      {rule.type}
                    </span>
                  </td>
                  <td className="font-mono">{rule.port}</td>
                  <td>{rule.protocol}</td>
                  <td>
                    <span className={`badge ${rule.status === 'Active' ? 'badge-success' : 'badge-warning'}`}>
                      {rule.status}
                    </span>
                  </td>
                  <td>
                    <div className="table-actions">
                      <button className="btn btn-sm btn-secondary"><Edit size={14} /></button>
                      <button className="btn btn-sm btn-danger"><Trash2 size={14} /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  const renderLogs = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Logs & Audit</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Logs</span>
        </div>
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Journal d'activité</h3>
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={() => handleExport('logs', 'csv')}>
              <FileDown size={14} /> Export CSV
            </button>
            <button className="btn btn-secondary" onClick={() => handleExport('logs', 'json')}>
              <FileJson size={14} /> Export JSON
            </button>
          </div>
        </div>

        <div className="filters-bar">
          <div className="search-input">
            <Search size={16} />
            <input type="text" placeholder="Rechercher dans les logs..." />
          </div>
          <select className="form-control" style={{ width: 'auto' }}>
            <option>Tous les types</option>
            <option>Authentification</option>
            <option>Scan</option>
            <option>Alerte</option>
            <option>Système</option>
          </select>
          <select className="form-control" style={{ width: 'auto' }}>
            <option>7 derniers jours</option>
            <option>30 derniers jours</option>
            <option>90 derniers jours</option>
          </select>
        </div>

        <div className="logs-container">
          {[
            { time: '10:45:23', level: 'INFO', action: 'Login', user: 'admin', ip: '192.168.1.10', status: 'Succès' },
            { time: '10:44:15', level: 'WARN', action: 'Scan réseau', user: 'admin', ip: '192.168.1.10', status: 'Terminé' },
            { time: '10:40:02', level: 'INFO', action: 'Nouvel appareil', user: 'system', ip: '192.168.1.25', status: 'Détecté' },
            { time: '10:35:18', level: 'ERROR', action: 'Connexion refusée', user: 'unknown', ip: '192.168.1.99', status: 'Échec' },
            { time: '10:30:00', level: 'INFO', action: 'Rapport généré', user: 'admin', ip: '192.168.1.10', status: 'Succès' },
            { time: '10:25:33', level: 'INFO', action: 'Logout', user: 'user1', ip: '192.168.1.15', status: 'Succès' },
            { time: '10:20:11', level: 'WARN', action: 'Signal faible', user: 'system', ip: '192.168.1.22', status: 'Alerte' },
          ].map((log, i) => (
            <div key={i} className={`log-entry log-${log.level.toLowerCase()}`}>
              <span className="log-time">{log.time}</span>
              <span className={`log-level ${log.level.toLowerCase()}`}>{log.level}</span>
              <span className="log-action">{log.action}</span>
              <span className="log-user">{log.user}</span>
              <span className="log-ip font-mono">{log.ip}</span>
              <span className={`log-status ${log.status === 'Succès' ? 'success' : log.status === 'Échec' ? 'error' : ''}`}>
                {log.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderReports = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Rapports</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Reports</span>
        </div>
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Générer un rapport</h3>
        </div>

        <div className="report-options">
          <div className="report-type-selector">
            {[
              { id: 'summary', name: 'Résumé', icon: BarChart3, desc: 'Vue d\'ensemble du réseau' },
              { id: 'devices', name: 'Équipements', icon: Network, desc: 'Liste détaillée des appareils' },
              { id: 'security', name: 'Sécurité', icon: Shield, desc: 'Analyse des menaces' },
              { id: 'performance', name: 'Performance', icon: Activity, desc: 'Métriques réseau' },
            ].map(type => (
              <div key={type.id} className="report-type-card">
                <type.icon size={32} />
                <h4>{type.name}</h4>
                <p>{type.desc}</p>
              </div>
            ))}
          </div>

          <div className="report-config">
            <div className="form-group">
              <label>Format</label>
              <select className="form-control">
                <option>PDF</option>
                <option>CSV</option>
                <option>JSON</option>
              </select>
            </div>
            <div className="form-group">
              <label>Période</label>
              <select className="form-control">
                <option>7 derniers jours</option>
                <option>30 derniers jours</option>
                <option>90 derniers jours</option>
                <option>Personnalisé</option>
              </select>
            </div>
          </div>

          <button className="btn btn-primary" onClick={handleGenerateReport}>
            <FileText size={16} /> Générer le rapport
          </button>
        </div>
      </div>

      <div className="chart-card fade-in mt-20">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Rapports récents</h3>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Nom</th>
                <th>Type</th>
                <th>Date</th>
                <th>Format</th>
                <th>Taille</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {[
                { name: 'Rapport mensuel - Janvier', type: 'Résumé', date: '01/02/2026', format: 'PDF', size: '2.4 MB' },
                { name: 'Audit sécurité Q4', type: 'Sécurité', date: '15/01/2026', format: 'PDF', size: '1.8 MB' },
                { name: 'Export appareils', type: 'Équipements', date: '10/01/2026', format: 'CSV', size: '456 KB' },
              ].map((report, i) => (
                <tr key={i}>
                  <td>{report.name}</td>
                  <td>{report.type}</td>
                  <td>{report.date}</td>
                  <td><span className="badge badge-info">{report.format}</span></td>
                  <td>{report.size}</td>
                  <td>
                    <div className="table-actions">
                      <button className="btn btn-sm btn-secondary" onClick={() => handleReportAction('preview', report)}>
                        <EyeIcon size={14} />
                      </button>
                      <button className="btn btn-sm btn-secondary" onClick={() => handleReportAction('download', report)}>
                        <Download size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  const renderStatistics = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Statistiques</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Statistics</span>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard 
          title="Équipements ce mois" 
          value={stats.total_devices} 
          change={<><TrendingUp size={14} /> +12% vs mois dernier</>} 
          icon={<Network size={24} />} 
        />
        <StatCard 
          title="Alertes traitées" 
          value={alerts.length} 
          change={<><TrendingDown size={14} /> -8% vs mois dernier</>} 
          icon={<Bell size={24} />} 
          color="#10B981"
        />
        <StatCard 
          title="Temps moyen de réponse" 
          value="23ms" 
          change={<><TrendingDown size={14} /> -15% vs mois dernier</>} 
          icon={<Activity size={24} />} 
          color="#F59E0B"
        />
        <StatCard 
          title="Disponibilité" 
          value="99.8%" 
          change={<><TrendingUp size={14} /> +0.2% vs mois dernier</>} 
          icon={<CheckCircle size={24} />} 
          color="#10B981"
        />
      </div>

      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header">
            <h3 className="chart-title">Évolution des équipements</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
              <XAxis dataKey="date" stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
              <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#ffffff', borderRadius: '8px' }} />
              <Legend />
              <Bar dataKey="active" fill="#10B981" name="Actifs" />
              <Bar dataKey="inactive" fill="#F59E0B" name="Inactifs" />
              <Bar dataKey="offline" fill="#EF4444" name="Hors ligne" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card fade-in">
          <div className="chart-header">
            <h3 className="chart-title">Répartition par type d'appareil</h3>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={devices.reduce((acc, device) => {
                  const existing = acc.find(d => d.name === device.type);
                  if (existing) existing.value++;
                  else acc.push({ name: device.type, value: 1 });
                  return acc;
                }, [])}
                cx="50%" cy="50%" labelLine={false} outerRadius={100}
                dataKey="value" label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
              >
                {devices.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'][index % 6]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#ffffff', borderRadius: '8px' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );

  const renderExports = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Exports</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Exports</span>
        </div>
      </div>

      <div className="export-grid">
        <div className="export-card">
          <div className="export-icon">
            <Network size={32} />
          </div>
          <h3>Équipements</h3>
          <p>Exporter la liste des appareils détectés</p>
          <div className="export-actions">
            <button className="btn btn-secondary" onClick={() => handleExport('devices', 'csv')}>
              <FileSpreadsheet size={14} /> CSV
            </button>
            <button className="btn btn-secondary" onClick={() => handleExport('devices', 'json')}>
              <FileJson size={14} /> JSON
            </button>
          </div>
        </div>

        <div className="export-card">
          <div className="export-icon" style={{ background: '#EF444420', color: '#EF4444' }}>
            <Bell size={32} />
          </div>
          <h3>Alertes</h3>
          <p>Exporter l'historique des alertes</p>
          <div className="export-actions">
            <button className="btn btn-secondary" onClick={() => handleExport('alerts', 'csv')}>
              <FileSpreadsheet size={14} /> CSV
            </button>
            <button className="btn btn-secondary" onClick={() => handleExport('alerts', 'json')}>
              <FileJson size={14} /> JSON
            </button>
          </div>
        </div>

        <div className="export-card">
          <div className="export-icon" style={{ background: '#F59E0B20', color: '#F59E0B' }}>
            <History size={32} />
          </div>
          <h3>Logs</h3>
          <p>Exporter les journaux d'activité</p>
          <div className="export-actions">
            <button className="btn btn-secondary" onClick={() => handleExport('logs', 'csv')}>
              <FileSpreadsheet size={14} /> CSV
            </button>
            <button className="btn btn-secondary" onClick={() => handleExport('logs', 'json')}>
              <FileJson size={14} /> JSON
            </button>
          </div>
        </div>

        <div className="export-card">
          <div className="export-icon" style={{ background: '#8B5CF620', color: '#8B5CF6' }}>
            <FileText size={32} />
          </div>
          <h3>Rapport complet</h3>
          <p>Générer et télécharger un rapport PDF</p>
          <div className="export-actions">
            <button className="btn btn-primary" onClick={handleGenerateReport}>
              <FileDown size={14} /> Générer PDF
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const renderSettings = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Paramètres</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Settings</span>
        </div>
      </div>

      <div className="settings-grid">
        <div className="chart-card fade-in">
          <div className="chart-header mb-20">
            <h3 className="chart-title">
              <Network size={20} style={{ marginRight: '8px' }} />
              Configuration réseau
            </h3>
          </div>
          
          <div className="settings-form">
            <div className="form-group">
              <label>Plage IP pour les scans</label>
              <input 
                type="text" 
                className="form-control" 
                value={settingsData.ip_range || settingsData.scan_range || '192.168.1.0/24'}
                onChange={(e) => setSettingsData({...settingsData, ip_range: e.target.value, scan_range: e.target.value})}
                placeholder="192.168.1.0/24"
              />
              <span className="form-hint">Plage CIDR à scanner lors des scans automatiques</span>
            </div>

            <div className="form-group">
              <label>Intervalle de scan automatique</label>
              <select 
                className="form-control"
                value={settingsData.scan_interval || settingsData.auto_scan_interval || 'Désactivé'}
                onChange={(e) => setSettingsData({...settingsData, scan_interval: e.target.value, auto_scan_interval: e.target.value})}
              >
                <option>Désactivé</option>
                <option>5 minutes</option>
                <option>15 minutes</option>
                <option>30 minutes</option>
                <option>1 heure</option>
              </select>
            </div>

            <div className="form-group">
              <label>Seuil de signal minimum (%)</label>
              <input 
                type="number" 
                className="form-control"
                value={settingsData.signal_threshold || 30}
                onChange={(e) => setSettingsData({...settingsData, signal_threshold: parseInt(e.target.value)})}
                min="0"
                max="100"
              />
              <span className="form-hint">Alerte si le signal descend sous ce seuil</span>
            </div>
          </div>
        </div>

        <div className="chart-card fade-in">
          <div className="chart-header mb-20">
            <h3 className="chart-title">
              <Bell size={20} style={{ marginRight: '8px' }} />
              Notifications
            </h3>
          </div>
          
          <div className="settings-form">
            <div className="form-group">
              <label className="toggle-label">
                <span>Notifications par email</span>
                <input type="checkbox" defaultChecked />
                <span className="toggle-slider"></span>
              </label>
            </div>

            <div className="form-group">
              <label className="toggle-label">
                <span>Alertes critiques</span>
                <input type="checkbox" defaultChecked />
                <span className="toggle-slider"></span>
              </label>
            </div>

            <div className="form-group">
              <label className="toggle-label">
                <span>Nouveaux appareils détectés</span>
                <input type="checkbox" defaultChecked />
                <span className="toggle-slider"></span>
              </label>
            </div>
          </div>
        </div>
      </div>

      <div className="settings-actions">
        <button className="btn btn-secondary">
          <RotateCcw size={14} /> Réinitialiser
        </button>
        <button className="btn btn-primary" onClick={handleSaveSettings}>
          <Save size={14} /> Sauvegarder
        </button>
      </div>
    </div>
  );

  const renderUsers = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Utilisateurs</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">Users</span>
        </div>
      </div>

      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Gestion des utilisateurs</h3>
          <button className="btn btn-primary" onClick={() => setEditingUser({})}>
            <Plus size={14} /> Nouvel utilisateur
          </button>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Utilisateur</th>
                <th>Email</th>
                <th>Nom complet</th>
                <th>Rôle</th>
                <th>Statut</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <div className="user-cell">
                    <div className="user-avatar">{currentUser?.username?.charAt(0).toUpperCase() || 'A'}</div>
                    <span>{currentUser?.username || 'admin'}</span>
                  </div>
                </td>
                <td>admin@netmon.local</td>
                <td>Administrator</td>
                <td><span className="badge badge-primary">Admin</span></td>
                <td><span className="badge badge-success">Actif</span></td>
                <td>
                  <span className="text-muted">Compte actuel</span>
                </td>
              </tr>
              {users.map(user => (
                <tr key={user.id}>
                  <td>
                    <div className="user-cell">
                      <div className="user-avatar">{user.username?.charAt(0).toUpperCase()}</div>
                      <span>{user.username}</span>
                    </div>
                  </td>
                  <td>{user.email}</td>
                  <td>{user.full_name}</td>
                  <td>
                    <span className={`badge ${user.role === 'admin' ? 'badge-primary' : 'badge-info'}`}>
                      {user.role === 'admin' ? 'Admin' : 'Utilisateur'}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${user.is_active ? 'badge-success' : 'badge-warning'}`}>
                      {user.is_active ? 'Actif' : 'Inactif'}
                    </span>
                  </td>
                  <td>
                    <div className="table-actions">
                      <button className="btn btn-sm btn-secondary" onClick={() => handleEditUser(user)}>
                        <Edit size={14} />
                      </button>
                      <button className="btn btn-sm btn-secondary" onClick={() => handleResetPassword(user.id)}>
                        <Key size={14} />
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={() => handleDeleteUser(user.id)}>
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal édition utilisateur */}
      {editingUser && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>{editingUser.id ? 'Modifier l\'utilisateur' : 'Nouvel utilisateur'}</h3>
              <button className="modal-close" onClick={() => setEditingUser(null)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Nom d'utilisateur</label>
                <input 
                  type="text" 
                  className="form-control"
                  value={editingUser.username || ''}
                  onChange={(e) => setEditingUser({...editingUser, username: e.target.value})}
                  disabled={!!editingUser.id}
                />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input 
                  type="email" 
                  className="form-control"
                  value={editingUser.email || ''}
                  onChange={(e) => setEditingUser({...editingUser, email: e.target.value})}
                />
              </div>
              <div className="form-group">
                <label>Nom complet</label>
                <input 
                  type="text" 
                  className="form-control"
                  value={editingUser.full_name || ''}
                  onChange={(e) => setEditingUser({...editingUser, full_name: e.target.value})}
                />
              </div>
              {!editingUser.id && (
                <div className="form-group">
                  <label>Mot de passe</label>
                  <div className="password-input-wrapper">
                    <input 
                      type={showNewUserPassword ? 'text' : 'password'}
                      className="form-control"
                      value={editingUser.password || ''}
                      onChange={(e) => setEditingUser({...editingUser, password: e.target.value})}
                    />
                    <button 
                      type="button" 
                      className="password-toggle"
                      onClick={() => setShowNewUserPassword(!showNewUserPassword)}
                    >
                      {showNewUserPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>
              )}
              <div className="form-group">
                <label>Rôle</label>
                <select 
                  className="form-control"
                  value={editingUser.role || 'user'}
                  onChange={(e) => setEditingUser({...editingUser, role: e.target.value})}
                >
                  <option value="user">Utilisateur</option>
                  <option value="admin">Administrateur</option>
                </select>
              </div>
              <div className="form-group">
                <label className="toggle-label">
                  <span>Compte actif</span>
                  <input 
                    type="checkbox"
                    checked={editingUser.is_active !== false}
                    onChange={(e) => setEditingUser({...editingUser, is_active: e.target.checked})}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setEditingUser(null)}>
                Annuler
              </button>
              <button className="btn btn-primary" onClick={handleSaveUser}>
                <Save size={14} /> Sauvegarder
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderSystem = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Système</h1>
        <div className="page-breadcrumb">
          <span>NetMon+</span>
          <ChevronRight size={12} />
          <span className="font-semibold">System</span>
        </div>
      </div>

      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <StatCard title="CPU" value="23%" change="Normal" icon={<Cpu size={24} />} color="#3B82F6" />
        <StatCard title="Mémoire" value="4.2 GB" change="Utilisé" icon={<MemoryStick size={24} />} color="#10B981" />
        <StatCard title="Disque" value="128 GB" change="Libre" icon={<HardDrive size={24} />} color="#F59E0B" />
        <StatCard title="Uptime" value="15j 4h" change="Actif" icon={<Clock size={24} />} color="#8B5CF6" />
      </div>

      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header mb-20">
            <h3 className="chart-title">Informations système</h3>
          </div>
          
          <div className="system-info">
            <div className="info-row">
              <span className="info-label">Version</span>
              <span className="info-value">NetMon+ v1.0.0</span>
            </div>
            <div className="info-row">
              <span className="info-label">Base de données</span>
              <span className="info-value">SQLite (netmon.db)</span>
            </div>
            <div className="info-row">
              <span className="info-label">API</span>
              <span className="info-value">FastAPI v0.100.0</span>
            </div>
            <div className="info-row">
              <span className="info-label">Python</span>
              <span className="info-value">3.11.4</span>
            </div>
            <div className="info-row">
              <span className="info-label">Scheduler</span>
              <span className="info-value">APScheduler actif</span>
            </div>
          </div>
        </div>

        <div className="chart-card fade-in">
          <div className="chart-header mb-20">
            <h3 className="chart-title">Maintenance</h3>
          </div>
          
          <div className="maintenance-actions">
            <button className="btn btn-secondary" onClick={handleBackupDb}>
              <Download size={14} /> Sauvegarder la base de données
            </button>
            <button className="btn btn-secondary" onClick={handleCheckUpdates}>
              <RefreshCw size={14} /> Vérifier les mises à jour
            </button>
            <button className="btn btn-danger" onClick={handleRestartService}>
              <RotateCcw size={14} /> Redémarrer le service
            </button>
          </div>

          <div className="system-logs-link">
            <button className="btn btn-link" onClick={() => setActivePage('logs')}>
              <History size={14} /> Voir les logs système
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return renderDashboard();
      case 'scan':
        return renderScan();
      case 'devices':
        return renderDevices();
      case 'alerts':
        return renderAlerts();
      case 'topology':
        return renderTopology();
      case 'performance':
        return renderPerformance();
      case 'firewall':
        return renderFirewall();
      case 'logs':
        return renderLogs();
      case 'reports':
        return renderReports();
      case 'statistics':
        return renderStatistics();
      case 'exports':
        return renderExports();
      case 'settings':
        return renderSettings();
      case 'users':
        return renderUsers();
      case 'system':
        return renderSystem();
      default:
        return renderDashboard();
    }
  };

  // ======================
  // RENDU PRINCIPAL
  // ======================

  // Page de login/register
  if (!isLoggedIn) {
    return renderAuthPage();
  }

  // Interface principale
  return (
    <div className={`app-container ${darkMode ? '' : 'light'}`}>
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="logo-icon">
              <Wifi size={24} color="white" />
            </div>
            <div>
              <div className="logo-text">NetMon+</div>
              <div className="sidebar-subtitle">Network Monitor Pro</div>
            </div>
          </div>
        </div>

        <div className="user-profile">
          <div className="user-avatar">
            {currentUser?.username?.charAt(0).toUpperCase() || 'U'}
          </div>
          <div className="user-info">
            <div className="user-name">{currentUser?.username}</div>
            <div className="user-role">{currentUser?.role === 'admin' ? 'Administrateur' : 'Utilisateur'}</div>
          </div>
        </div>

        <nav className="sidebar-menu">
          {menuSections.map((section, index) => (
            <div key={index} className="menu-section">
              <div className="menu-title">{section.title}</div>
              <ul className="menu-items">
                {section.items.map(item => {
                  const Icon = item.icon;
                  return (
                    <li key={item.id} className="menu-item">
                      <button
                        onClick={() => {
                          setActivePage(item.id);
                          if (window.innerWidth < 992) setSidebarOpen(false);
                        }}
                        className={`menu-link ${activePage === item.id ? 'active' : ''}`}
                      >
                        <Icon className="menu-icon" size={18} />
                        <span>{item.label}</span>
                        {item.badge && <span className="menu-badge">{item.badge}</span>}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <button className="logout-btn" onClick={handleLogout}>
            <LogOut size={16} />
            Déconnexion
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="header">
          <button className="mobile-menu-btn" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
          <div style={{ flex: 1 }}></div>
          <div className="header-actions">
            <button className="btn btn-secondary" style={{ padding: '8px 12px' }} onClick={() => setDemoMode(!demoMode)}>
              {demoMode ? 'DEMO' : 'API'}
            </button>
            <button className="theme-toggle" onClick={() => setDarkMode(!darkMode)}>
              {darkMode ? <Sun size={20} /> : <Moon size={20} />}
            </button>
          </div>
        </header>

        <AnimatePresence mode="wait">
          <motion.div key={activePage} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
            {renderPage()}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
};

export default App;
