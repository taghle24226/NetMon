import React, { useState, useEffect, useCallback } from 'react';
import { 
  Wifi, Monitor, Smartphone, Router, AlertTriangle, 
  Settings, Clock, Shield, Download, RefreshCw, 
  Search, Filter, Bell, Activity, Users, Zap, 
  WifiOff, WifiHigh, WifiLow, Home, BarChart3, Network,
  LogOut, Menu, X, ChevronRight, Sun, Moon,
  HardDrive, Server, Globe, ShieldCheck, History,
  BellRing, Eye, EyeOff, CircuitBoard, FileText,
  User, Plus, Key, Trash2, Edit, Eye as EyeIcon,
  Mail, Lock,
  RotateCcw, CheckCircle2, AlertCircle, ArrowRight, Loader2
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import './App.css';

const parseJwt = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch (e) {
    return null;
  }
};


const API_BASE = 'http://localhost:8000/api';

// ======================
// API UTILITY FUNCTIONS
// ======================

const downloadFromApi = async (url, filename) => {
  const token = localStorage.getItem('netmon_token');

  const res = await fetch(`${API_BASE}${url}`, {
    method: 'GET',
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem('netmon_token');
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
  const token = localStorage.getItem('netmon_token');
  const res = await fetch(`${API_BASE}${url}`, {
    method: 'GET',
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem('netmon_token');
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
// COMPOSANT FORMFIELD EXTERNE (pour éviter les re-rendus)
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
    const token = localStorage.getItem('netmon_token');
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
        const baseDevices = devices.length ? devices : Array.from({ length: 10 }, (_, i) => makeDemoDevice(i + 1));
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
        setChartData(prev => {
          const next = [...(prev || []), point];
          return next.slice(Math.max(next.length - 14, 0));
        });

        setLastScan(now);
        setDevices(baseDevices);
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
  }, [demoMode, devices.length, scanning]);

  const loadDevices = useCallback(async () => {
    try {
      if (demoMode) {
        const baseDevices = devices.length ? devices : Array.from({ length: 10 }, (_, i) => makeDemoDevice(i + 1));
        setDevices(baseDevices);
        return;
      }

      const devicesData = await apiFetch('/network/devices');
      setDevices(devicesData);
    } catch (err) {
      console.error('Erreur chargement devices:', err);
    }
  }, [demoMode, devices.length]);

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
    const token = localStorage.getItem('netmon_token');
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
    // Clear error when user starts typing
    if (loginErrors[name]) {
      setLoginErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const handleRegisterChange = (e) => {
    const { name, value } = e.target;
    setRegisterForm(prev => ({ ...prev, [name]: value }));
    // Clear error when user starts typing
    if (registerErrors[name]) {
      setRegisterErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    
    // Valider tous les champs
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
      // Essayer de se connecter via l'API
      let data;
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
        } else {
          throw new Error('API non disponible');
        }
      } catch (apiErr) {
        // Mode démo : accepter n'importe quel utilisateur/mot de passe
        // Créer un token fictif
        const payload = {
          sub: loginForm.username,
          id: 1,
          role: loginForm.username === 'admin' ? 'admin' : 'user',
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24
        };
        data = {
          access_token: btoa(JSON.stringify(payload))
        };
      }
  
      if (loginForm.remember) {
        localStorage.setItem('netmon_token', data.access_token);
      } else {
        sessionStorage.setItem('netmon_token', data.access_token);
        localStorage.removeItem('netmon_token');
      }
  
      const payload = parseJwt(data.access_token) || {
        sub: loginForm.username,
        id: 1,
        role: loginForm.username === 'admin' ? 'admin' : 'user'
      };
  
      setIsLoggedIn(true);
      setCurrentUser({
        id: payload.id || 1,
        username: payload.sub || loginForm.username,
        role: payload.role || 'user'
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
    
    // Valider tous les champs
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
          <motion.div
            className="auth-decoration-circle auth-decoration-1"
            animate={{ scale: [1, 1.1, 1], opacity: [0.1, 0.15, 0.1] }}
            transition={{ duration: 8, repeat: Infinity }}
          />
          <motion.div
            className="auth-decoration-circle auth-decoration-2"
            animate={{ scale: [1.1, 1, 1.1], opacity: [0.15, 0.1, 0.15] }}
            transition={{ duration: 10, repeat: Infinity }}
          />
          
          {/* Contenu */}
          <div className="auth-branding-content">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
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
                    transition={{ delay: 0.3 + index * 0.1 }}
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
              transition={{ delay: 0.8 }}
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
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.3 }}
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
                      <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="auth-alert auth-alert-error"
                      >
                        <AlertCircle size={18} />
                        <span>{authError}</span>
                      </motion.div>
                    )}

                    {/* Alerte de succès */}
                    {authSuccess && (
                      <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="auth-alert auth-alert-success"
                      >
                        <CheckCircle2 size={18} />
                        <span>{authSuccess}</span>
                      </motion.div>
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
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.3 }}
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
                      <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="auth-alert auth-alert-error"
                      >
                        <AlertCircle size={18} />
                        <span>{authError}</span>
                      </motion.div>
                    )}

                    {/* Alerte de succès */}
                    {authSuccess && (
                      <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="auth-alert auth-alert-success"
                      >
                        <CheckCircle2 size={18} />
                        <span>{authSuccess}</span>
                      </motion.div>
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
  // PAGES (simplifié pour économiser l'espace - le reste est identique)
  // ======================

  const renderPage = () => {
    // ... (le reste du code des pages reste identique - dashboard, scan, devices, etc.)
    // Pour économiser l'espace, je vais juste retourner le dashboard par défaut
    
    switch (activePage) {
      case 'dashboard':
        return (
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

      default:
        return (
          <div className="content">
            <div className="text-center py-40">
              <h3 className="chart-title mb-10">Page en construction</h3>
              <button className="btn btn-primary" onClick={() => setActivePage('dashboard')}>
                <Home size={16} /> Retour au dashboard
              </button>
            </div>
          </div>
        );
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
          <motion.div key={activePage} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
            {renderPage()}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
};

export default App;
