import React, { useState, useEffect, useCallback } from 'react';
import { 
  Wifi, Monitor, Smartphone, Router, AlertTriangle, 
  Settings, Clock, Shield, Download, RefreshCw, 
  Search, Filter, Bell, Activity, Users, Zap, 
  WifiOff, WifiHigh, WifiLow, Home, BarChart3, Network,
  LogOut, Menu, X, ChevronRight, Sun, Moon,
  HardDrive, Server, Globe, ShieldCheck, History,
  BellRing, Eye, CircuitBoard, Calendar, FileText,
  User, Plus, Key, Trash2, Edit, Eye as EyeIcon,
  RotateCcw
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
// API UTILITY FUNCTIONS (moved out of apiFetch)
// ======================

const downloadFromApi = async (url, filename) => {
  const token = localStorage.getItem('netmon_token');

  const res = await fetch(`${API_BASE}${url}`, {
    method: 'GET',
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  if (!res.ok) {
    if (res.status === 401) handleLogout();
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
    if (res.status === 401) handleLogout();
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
  const [loginError, setLoginError] = useState('');
  const [registerMode, setRegisterMode] = useState(false);
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ 
    username: '', 
    email: '', 
    full_name: '', 
    password: '', 
    confirm_password: '',
    role: 'user'
  });
  const [users, setUsers] = useState([]);
  const [editingUser, setEditingUser] = useState(null);
  const [settingsData, setSettingsData] = useState({
    scan_range: '',
    auto_scan_interval: 'Désactivé',
    signal_threshold: 30
  });

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

  const IconActionButton = ({ variant = 'secondary', title, onClick, children }) => (
    <button
      type="button"
      className={`btn btn-${variant}`}
      style={{ padding: '6px 12px' }}
      title={title}
      onClick={onClick}
    >
      {children}
    </button>
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
        handleLogout();
        throw new Error('Session expirée. Veuillez vous reconnecter.');
      }
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Erreur ${res.status}`);
    }
    return res.json();
  };

  const loadDashboardData = useCallback(async () => {
    try {
      const statsData = await apiFetch('/dashboard/stats');
      const chart = await apiFetch('/dashboard/chart-data');
      setStats(statsData);
      setChartData(chart);
      setLastScan(statsData.last_scan ? new Date(statsData.last_scan) : null);
      setScanning(statsData.scanning || false);
    } catch (err) {
      console.error('Erreur chargement dashboard:', err);
    }
  }, []);

  const loadDevices = useCallback(async () => {
    try {
      const devicesData = await apiFetch('/network/devices');
      setDevices(devicesData);
    } catch (err) {
      console.error('Erreur chargement devices:', err);
    }
  }, []);

  const loadAlerts = useCallback(async () => {
    try {
      const alertsData = await apiFetch('/alerts');
      setAlerts(alertsData);
    } catch (err) {
      console.error('Erreur chargement alertes:', err);
    }
  }, []);

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
  }, [isLoggedIn, loadDashboardData, loadDevices, loadAlerts, loadUsers, currentUser]);

  // ======================
  // AUTHENTIFICATION
  // ======================

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
  
    setLoginError('');
    try {
      const data = await apiFetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          username: loginForm.username,
          password: loginForm.password
        })
      });
  
      localStorage.setItem('netmon_token', data.access_token);
  
      const payload = parseJwt(data.access_token);
  
      setIsLoggedIn(true);
      setCurrentUser({
        id: payload.id,
        username: payload.sub,
        role: payload.role || 'user'
      });
  
      setActivePage('dashboard');
    } catch (err) {
      setLoginError(err.message || 'Erreur de connexion');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (registerForm.password !== registerForm.confirm_password) {
      setLoginError('Les mots de passe ne correspondent pas');
      return;
    }
    try {
      await apiFetch('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          username: registerForm.username,
          email: registerForm.email,
          full_name: registerForm.full_name,
          password: registerForm.password,
          role: registerForm.role
        })
      });
      setLoginForm({ username: registerForm.username, password: registerForm.password });
      setRegisterMode(false);
      setTimeout(handleLogin, 100);
    } catch (err) {
      setLoginError(err.message || 'Erreur lors de l’inscription');
    }
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setCurrentUser(null);
    localStorage.removeItem('netmon_token');
    setActivePage('dashboard');
  };

  const startScan = async () => {
    try {
      setScanning(true);
      await apiFetch('/network/scan', { method: 'POST' });
      setTimeout(() => {
        loadDevices();
        loadDashboardData();
        setScanning(false);
      }, 5000);
    } catch (err) {
      console.error('Erreur scan:', err);
      setScanning(false);
    }
  };

  // ======================
  // ACTIONS (BOUTONS UI) - DÉDUPLIQUÉS
  // ======================

  const handleResolveAlert = async (alertId) => {
    try {
      await apiFetch(`/alerts/${alertId}/resolve`, { method: 'POST' });
      await loadAlerts();
      await loadDashboardData();
    } catch (err) {
      alert('Erreur: ' + err.message);
    }
  };

  const handleGenerateReport = async () => {
    try {
      await downloadFromApi('/reports/export?format=pdf', `rapport_netmon_${Date.now()}.pdf`);
      alert('Rapport généré et téléchargé.');
    } catch (err) {
      alert('Erreur: ' + err.message);
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

      if (f === 'json') {
        const data = await apiFetch(`/exports/${t}?format=json`);
        downloadJsonFile(data, `${t}.json`);
        return;
      }

      await downloadFromApi(`/exports/${t}?format=csv`, `${t}.csv`);
    } catch (err) {
      alert('Erreur: ' + err.message);
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
      const msg =
        typeof err.message === 'string'
          ? err.message
          : err.message?.detail || 'Erreur lors de la sauvegarde';
  
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
        // ➕ CRÉATION (ADMIN)
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
        // ✏️ MODIFICATION
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
      const msg =
        typeof err.message === 'string'
          ? err.message
          : err.message?.detail || 'Erreur lors de la sauvegarde utilisateur';
  
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
  // PAGES
  // ======================

  const renderPage = () => {
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
              <StatCard 
                title="Équipements totaux" 
                value={stats.total_devices} 
                change="Données en temps réel" 
                icon={<Users size={24} />} 
              />
              <StatCard 
                title="Équipements actifs" 
                value={stats.active_devices} 
                change="Surveillance active" 
                icon={<WifiHigh size={24} />} 
                color="#10B981" 
              />
              <StatCard 
                title="Équipements inactifs" 
                value={stats.inactive_devices} 
                change="À surveiller" 
                icon={<WifiLow size={24} />} 
                color="#F59E0B" 
                positive={false}
              />
              <StatCard 
                title="Équipements hors ligne" 
                value={stats.offline_devices} 
                change="Intervention requise" 
                icon={<WifiOff size={24} />} 
                color="#EF4444" 
                positive={false}
              />
            </div>

            {/* Graphiques */}
            <div className="charts-grid">
              <div className="chart-card fade-in">
                <div className="chart-header">
                  <h3 className="chart-title">Activité réseau (7 jours)</h3>
                  <div className="chart-actions">
                    <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                      <RefreshCw size={14} /> Actualiser
                    </button>
                  </div>
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
                  <h3 className="chart-title">Répartition par type d'appareil</h3>
                  <div className="chart-actions">
                    <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                      <RefreshCw size={14} /> Actualiser
                    </button>
                  </div>
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={devices.reduce((acc, device) => {
                        const existing = acc.find(d => d.name === device.type);
                        if (existing) {
                          existing.value++;
                        } else {
                          acc.push({ name: device.type, value: 1, color: device.color || '#3B82F6' });
                        }
                        return acc;
                      }, [])}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={100}
                      innerRadius={40}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
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

            {/* Alertes */}
            <div className="alert-card fade-in">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Alertes récentes</h3>
                <button className="btn btn-secondary" onClick={() => setActivePage('alerts')}>
                  <Bell size={14} /> Voir toutes
                </button>
              </div>
              <div className="space-y-12">
                {alerts.slice(0, 4).map(alert => (
                  <div 
                    key={alert.id} 
                    className={`alert-item alert-${alert.severity === 'critical' ? 'critical' : alert.severity === 'warning' ? 'warning' : 'info'}`}
                  >
                    <div className="flex items-center gap-12">
                      <AlertTriangle size={18} />
                      <div>
                        <div className="font-semibold mb-2">{alert.message}</div>
                        <div className="text-sm opacity-75">Il y a {alert.time_ago}</div>
                      </div>
                    </div>
                    <button className="btn btn-secondary" style={{ padding: '8px 16px' }}>
                      <Shield size={14} /> Résoudre
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan rapide */}
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
                  <button
                    onClick={startScan}
                    disabled={scanning}
                    className="btn btn-primary"
                  >
                    {scanning ? (
                      <>
                        <RefreshCw className="animate-spin" size={16} />
                        Scan en cours...
                      </>
                    ) : (
                      <>
                        <Search size={16} />
                        Lancer un scan
                      </>
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

      case 'scan':
        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Scan Réseau</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Surveillance</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Scan Réseau</span>
              </div>
            </div>

            <div className="chart-card mb-30">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Scanner le réseau</h3>
                <button className="btn btn-secondary">
                  <Settings size={14} /> Paramètres
                </button>
              </div>
              
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-20 mb-30">
                <div>
                  <p className="mb-10">Détectez tous les équipements connectés à votre réseau local</p>
                  <div className="flex items-center gap-10 text-sm opacity-75">
                    <Globe size={14} />
                    <span>Plage IP: 192.168.1.0/24</span>
                  </div>
                </div>
                <button
                  onClick={startScan}
                  disabled={scanning}
                  className="btn btn-primary"
                  style={{ padding: '15px 30px' }}
                >
                  {scanning ? (
                    <>
                      <RefreshCw className="animate-spin" size={18} />
                      Scanning en cours...
                    </>
                  ) : (
                    <>
                      <Search size={18} />
                      Lancer le scan
                    </>
                  )}
                </button>
              </div>

              {lastScan && (
                <div className="p-20 rounded-lg" style={{ 
                  backgroundColor: darkMode ? 'rgba(59, 130, 246, 0.1)' : 'rgba(59, 130, 246, 0.05)',
                  border: `1px solid ${darkMode ? 'rgba(59, 130, 246, 0.3)' : 'rgba(59, 130, 246, 0.2)'}`
                }}>
                  <div className="flex items-center gap-10">
                    <Clock size={16} />
                    <span>Dernier scan effectué: {lastScan.toLocaleString()}</span>
                  </div>
                </div>
              )}
            </div>

            <div className="chart-card">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Appareils détectés ({devices.length})</h3>
                <div className="flex items-center gap-10">
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <RefreshCw size={14} /> Actualiser
                  </button>
                  <button className="btn btn-secondary">
                    <Download size={14} /> Exporter
                  </button>
                  <button className="btn btn-secondary">
                    <Filter size={14} /> Filtrer
                  </button>
                </div>
              </div>
              {renderDevicesTable(true)}
            </div>
          </div>
        );

      case 'devices':
        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Équipements</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Surveillance</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Équipements</span>
              </div>
            </div>

            <div className="chart-card">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Inventaire des équipements ({devices.length})</h3>
                <div className="flex items-center gap-10">
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <RefreshCw size={14} /> Actualiser
                  </button>
                  <button className="btn btn-primary" onClick={startScan}>
                    <Search size={14} /> Lancer un scan
                  </button>
                </div>
              </div>
              {renderDevicesTable(false)}
            </div>
          </div>
        );

      case 'alerts':
        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Alertes de sécurité</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Sécurité</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Alertes</span>
              </div>
            </div>

            <div className="flex items-center justify-between mb-30">
              <div>
                <h2 className="chart-title mb-10">Alertes intelligentes</h2>
                <p className="opacity-75">Surveillance en temps réel de votre réseau</p>
              </div>
              <div className="flex items-center gap-10">
                <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                  <RefreshCw size={16} /> Actualiser
                </button>
                <button className="btn btn-primary">
                  <Bell size={16} /> Configurer alertes
                </button>
              </div>
            </div>

            <div className="space-y-20">
              {alerts.map(alert => {
                const severityClass = alert.severity === 'critical' ? 'alert-critical' : 
                                   alert.severity === 'warning' ? 'alert-warning' : 'alert-info';
                const severityIcon = alert.severity === 'critical' ? '🔴' : 
                                   alert.severity === 'warning' ? '🟡' : '🔵';
                
                return (
                  <div key={alert.id} className={`alert-item ${severityClass} fade-in`}>
                    <div className="flex items-start gap-12">
                      <div className="text-xl">{severityIcon}</div>
                      <div>
                        <div className="font-semibold mb-2">{alert.message}</div>
                        <div className="flex items-center gap-20 text-sm opacity-75">
                          <span>Type: {alert.alert_type}</span>
                          <span>•</span>
                          <span>Il y a: {alert.time_ago}</span>
                          <span>•</span>
                          <span>Priorité: {alert.severity}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-10">
                      <button className="btn btn-secondary">
                        <EyeIcon size={14} /> Détails
                      </button>
                      <button className="btn btn-primary">
                        <Shield size={14} /> Résoudre
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );

        case 'topology': {
          const center = { x: 400, y: 260 };
          const radius = 180;
        
          const positionedDevices = devices.map((d, i) => {
            const angle = (2 * Math.PI / Math.max(devices.length, 1)) * i;
            return {
              ...d,
              x: center.x + radius * Math.cos(angle),
              y: center.y + radius * Math.sin(angle)
            };
          });
        
          const statusColor = (status) => {
            if (status === 'Active') return '#10B981';
            if (status === 'Inactive') return '#F59E0B';
            return '#EF4444';
          };
        
          return (
            <div className="content">
              <div className="page-title mb-30">
                <h1>Topologie réseau avancée</h1>
                <div className="page-breadcrumb">
                  <span>NetMon+</span>
                  <ChevronRight size={12} />
                  <span className="font-semibold">Topologie</span>
                </div>
              </div>
        
              <div className="chart-card">
                <div className="chart-header mb-20">
                  <h3 className="chart-title">Carte réseau animée</h3>
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <RefreshCw size={14} /> Actualiser
                  </button>
                </div>
        
                <svg width="100%" height="540" viewBox="0 0 800 540">
                  {/* LIGNES */}
                  {positionedDevices.map(dev => (
                    <motion.line
                      key={`line-${dev.id}`}
                      x1={center.x}
                      y1={center.y}
                      x2={dev.x}
                      y2={dev.y}
                      stroke={statusColor(dev.status)}
                      strokeWidth="2"
                      initial={{ pathLength: 0 }}
                      animate={{ pathLength: 1 }}
                      transition={{ duration: 0.8 }}
                    />
                  ))}
        
                  {/* ROUTEUR CENTRAL */}
                  <motion.circle
                    cx={center.x}
                    cy={center.y}
                    r="28"
                    fill="#3B82F6"
                    animate={{ scale: [1, 1.15, 1] }}
                    transition={{ repeat: Infinity, duration: 2 }}
                  />
                  <text x={center.x} y={center.y + 50} textAnchor="middle" fill="#94a3b8">
                    Routeur
                  </text>
        
                  {/* APPAREILS */}
                  {positionedDevices.map(dev => (
                    <motion.g
                      key={dev.id}
                      initial={{ scale: 0, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      transition={{ delay: 0.2 }}
                    >
                      <circle
                        cx={dev.x}
                        cy={dev.y}
                        r="20"
                        fill={statusColor(dev.status)}
                      />
                      <text
                        x={dev.x}
                        y={dev.y + 35}
                        textAnchor="middle"
                        fontSize="11"
                        fill="#cbd5f5"
                      >
                        {dev.name}
                      </text>
                    </motion.g>
                  ))}
                </svg>
        
                <div className="flex justify-center gap-30 mt-20">
                  <div className="flex items-center gap-8">
                    <span style={{ width: 12, height: 12, background: '#10B981', borderRadius: '50%' }} />
                    Actif
                  </div>
                  <div className="flex items-center gap-8">
                    <span style={{ width: 12, height: 12, background: '#F59E0B', borderRadius: '50%' }} />
                    Inactif
                  </div>
                  <div className="flex items-center gap-8">
                    <span style={{ width: 12, height: 12, background: '#EF4444', borderRadius: '50%' }} />
                    Hors ligne
                  </div>
                </div>
              </div>
            </div>
          );
        }

      case 'performance':
        const latencyData = Array.from({length: 24}, (_, i) => ({
          hour: `${i}h`,
          latency: 10 + Math.random() * 40
        }));

        const bandwidthData = [
          { name: 'Upload', value: Math.floor(Math.random() * 20) + 5 },
          { name: 'Download', value: Math.floor(Math.random() * 100) + 50 }
        ];

        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Performance réseau</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Surveillance</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Performance</span>
              </div>
            </div>

            <div className="charts-grid">
              <div className="chart-card fade-in">
                <div className="chart-header">
                  <h3 className="chart-title">Latence (ms)</h3>
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <RefreshCw size={14} /> Actualiser
                  </button>
                </div>
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={latencyData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
                    <XAxis dataKey="hour" stroke={darkMode ? '#94a3b8' : '#64748b'} />
                    <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
                    <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', borderRadius: '8px' }} />
                    <Line type="monotone" dataKey="latency" stroke="#8B5CF6" strokeWidth={2} dot={{ r: 3 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-card fade-in">
                <div className="chart-header">
                  <h3 className="chart-title">Utilisation bande passante</h3>
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <RefreshCw size={14} /> Actualiser
                  </button>
                </div>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={bandwidthData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
                    <XAxis dataKey="name" stroke={darkMode ? '#94a3b8' : '#64748b'} />
                    <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
                    <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', borderRadius: '8px' }} />
                    <Bar dataKey="value" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="chart-card mt-30">
              <div className="chart-header">
                <h3 className="chart-title">Indicateurs clés</h3>
                <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                  <RefreshCw size={14} /> Actualiser
                </button>
              </div>
              <div className="stats-grid">
                <StatCard 
                  title="Débit moyen" 
                  value={`${bandwidthData[1].value} Mbps`} 
                  change="+5% vs hier" 
                  icon={<Activity size={24} />} 
                />
                <StatCard 
                  title="Paquets perdus" 
                  value="0.02%" 
                  change="Stable" 
                  icon={<Network size={24} />} 
                />
                <StatCard 
                  title="Jitter" 
                  value="3 ms" 
                  change="↑ 1 ms" 
                  icon={<Zap size={24} />} 
                  positive={false}
                />
                <StatCard 
                  title="Uptime" 
                  value="99.98%" 
                  change="Excellent" 
                  icon={<Server size={24} />} 
                />
              </div>
            </div>
          </div>
        );

      case 'firewall':
        const firewallRules = [
          { id: 1, name: 'Accès Web', source: 'LAN', dest: 'WAN', port: '80,443', action: 'Autoriser', status: 'Active' },
          { id: 2, name: 'SSH Admin', source: '192.168.1.50', dest: 'WAN', port: '22', action: 'Autoriser', status: 'Active' },
          { id: 3, name: 'Bloquer Torrent', source: 'LAN', dest: 'ANY', port: '6881-6889', action: 'Bloquer', status: 'Active' }
        ];

        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Firewall</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Sécurité</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Firewall</span>
              </div>
            </div>

            <div className="chart-card mb-30">
              <div className="chart-header">
                <h3 className="chart-title">Règles actives ({firewallRules.length})</h3>
                <button className="btn btn-primary">
                  <Plus size={14} /> Nouvelle règle
                </button>
              </div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Règle</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>Action</th>
                      <th>Statut</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {firewallRules.map(rule => (
                      <tr key={rule.id}>
                        <td>{rule.name}</td>
                        <td>{rule.source}</td>
                        <td>{rule.dest}</td>
                        <td>{rule.port}</td>
                        <td>
                          <span className={`badge ${rule.action === 'Autoriser' ? 'badge-success' : 'badge-danger'}`}>
                            {rule.action}
                          </span>
                        </td>
                        <td>
                          <span className="badge badge-success">{rule.status}</span>
                        </td>
                        <td>
                          <div className="flex gap-10">
                            <button className="btn btn-secondary" style={{ padding: '6px 12px' }}>
                              <Edit size={14} />
                            </button>
                            <button className="btn btn-danger" style={{ padding: '6px 12px' }}>
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

            <div className="chart-card">
              <div className="chart-header">
                <h3 className="chart-title">Trafic bloqué (24h)</h3>
                <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                  <RefreshCw size={14} /> Actualiser
                </button>
              </div>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={[
                  { hour: '00h', blocked: 12 },
                  { hour: '06h', blocked: 5 },
                  { hour: '12h', blocked: 28 },
                  { hour: '18h', blocked: 45 }
                ]}>
                  <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
                  <XAxis dataKey="hour" stroke={darkMode ? '#94a3b8' : '#64748b'} />
                  <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
                  <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', borderRadius: '8px' }} />
                  <Bar dataKey="blocked" fill="#EF4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        );

      case 'logs':
        const mockLogs = [
          { id: 1, time: '10:23', action: 'Login', user: 'admin', ip: '192.168.1.10', status: 'Succès' },
          { id: 2, time: '10:25', action: 'Scan réseau', user: 'admin', ip: '192.168.1.10', status: 'Succès' },
          { id: 3, time: '10:30', action: 'Export rapport', user: 'admin', ip: '192.168.1.10', status: 'Succès' },
          { id: 4, time: '10:32', action: 'Tentative login', user: 'inconnu', ip: '203.0.113.5', status: 'Échec' },
        ];

        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Logs & Audit</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Sécurité</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Logs & Audit</span>
              </div>
            </div>

            <div className="chart-card mb-30">
              <div className="chart-header">
                <h3 className="chart-title">Journal des événements ({mockLogs.length})</h3>
                <div className="flex items-center gap-10">
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <Filter size={14} /> Filtrer
                  </button>
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <Download size={14} /> Exporter
                  </button>
                </div>
              </div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Heure</th>
                      <th>Action</th>
                      <th>Utilisateur</th>
                      <th>IP source</th>
                      <th>Statut</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mockLogs.map(log => (
                      <tr key={log.id}>
                        <td>{log.time}</td>
                        <td>{log.action}</td>
                        <td>{log.user}</td>
                        <td className="font-mono">{log.ip}</td>
                        <td>
                          <span className={`badge ${log.status === 'Succès' ? 'badge-success' : 'badge-danger'}`}>
                            {log.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );

      case 'reports':
        const reports = [
          { id: 1, name: 'Rapport quotidien', date: '23 janv. 2026', size: '1.2 Mo', format: 'PDF' },
          { id: 2, name: 'Audit sécurité', date: '22 janv. 2026', size: '3.4 Mo', format: 'PDF' },
          { id: 3, name: 'Topologie réseau', date: '20 janv. 2026', size: '0.8 Mo', format: 'PNG' },
        ];

        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Rapports</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Rapports</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Rapports</span>
              </div>
            </div>

            <div className="chart-card mb-30">
              <div className="chart-header">
                <h3 className="chart-title">Rapports générés ({reports.length})</h3>
                <button className="btn btn-primary" onClick={handleGenerateReport}>
                  <FileText size={14} /> Nouveau rapport
                </button>
              </div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Nom</th>
                      <th>Date</th>
                      <th>Format</th>
                      <th>Taille</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reports.map(report => (
                      <tr key={report.id}>
                        <td>{report.name}</td>
                        <td>{report.date}</td>
                        <td>
                          <span className="badge badge-info">{report.format}</span>
                        </td>
                        <td>{report.size}</td>
                        <td>
                          <div className="flex gap-10">
                            <button className="btn btn-secondary" style={{ padding: '6px 12px' }} onClick={() => handleReportAction('preview', report)}>
                              <EyeIcon size={14} />
                            </button>
                            <button className="btn btn-secondary" style={{ padding: '6px 12px' }} onClick={() => handleReportAction('download', report)}>
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

      case 'statistics':
        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Statistiques</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Rapports</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Statistiques</span>
              </div>
            </div>

            <div className="charts-grid">
              <div className="chart-card fade-in">
                <div className="chart-header">
                  <h3 className="chart-title">Évolution des appareils</h3>
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <RefreshCw size={14} /> Actualiser
                  </button>
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={[
                    { month: 'Jan', devices: 10 },
                    { month: 'Fév', devices: 12 },
                    { month: 'Mar', devices: 15 },
                    { month: 'Avr', devices: 14 },
                    { month: 'Mai', devices: 18 },
                    { month: 'Jun', devices: 20 }
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
                    <XAxis dataKey="month" stroke={darkMode ? '#94a3b8' : '#64748b'} />
                    <YAxis stroke={darkMode ? '#94a3b8' : '#64748b'} />
                    <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', borderRadius: '8px' }} />
                    <Line type="monotone" dataKey="devices" stroke="#3B82F6" strokeWidth={3} dot={{ r: 5 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-card fade-in">
                <div className="chart-header">
                  <h3 className="chart-title">Répartition des alertes</h3>
                  <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                    <RefreshCw size={14} /> Actualiser
                  </button>
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Critiques', value: 5, color: '#EF4444' },
                        { name: 'Avertissements', value: 12, color: '#F59E0B' },
                        { name: 'Infos', value: 25, color: '#10B981' }
                      ]}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    >
                      {[
                        { name: 'Critiques', value: 5, color: '#EF4444' },
                        { name: 'Avertissements', value: 12, color: '#F59E0B' },
                        { name: 'Infos', value: 25, color: '#10B981' }
                      ].map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        );

      case 'exports':
        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Exports</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Rapports</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Exports</span>
              </div>
            </div>

            <div className="chart-card">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Exporter les données</h3>
                <p className="opacity-75">Sélectionnez les données à exporter et le format souhaité.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-20">
                <div className="p-20 border rounded-lg" style={{ borderColor: darkMode ? '#334155' : '#e2e8f0' }}>
                  <h4 className="font-semibold mb-10">Équipements</h4>
                  <button className="btn btn-secondary w-full mt-10" onClick={() => handleExport('devices','csv')}>
                    <Download size={14} /> Exporter CSV
                  </button>
                  <button className="btn btn-secondary w-full mt-10" onClick={() => handleExport('devices','json')}>
                    <Download size={14} /> Exporter JSON
                  </button>
                </div>
                <div className="p-20 border rounded-lg" style={{ borderColor: darkMode ? '#334155' : '#e2e8f0' }}>
                  <h4 className="font-semibold mb-10">Alertes</h4>
                  <button className="btn btn-secondary w-full mt-10" onClick={() => handleExport('alerts','csv')}>
                    <Download size={14} /> Exporter CSV
                  </button>
                  <button className="btn btn-secondary w-full mt-10" onClick={() => handleExport('alerts','json')}>
                    <Download size={14} /> Exporter JSON
                  </button>
                </div>
                <div className="p-20 border rounded-lg" style={{ borderColor: darkMode ? '#334155' : '#e2e8f0' }}>
                  <h4 className="font-semibold mb-10">Logs</h4>
                  <button className="btn btn-secondary w-full mt-10" onClick={() => handleExport('logs','csv')}>
                    <Download size={14} /> Exporter CSV
                  </button>
                  <button className="btn btn-secondary w-full mt-10" onClick={() => handleExport('logs','json')}>
                    <Download size={14} /> Exporter JSON
                  </button>
                </div>
              </div>
            </div>
          </div>
        );

        case 'settings':
          return (
            <div className="content">
              <div className="page-title mb-30">
                <h1>Paramètres</h1>
                <div className="page-breadcrumb">
                  <span>NetMon+</span>
                  <ChevronRight size={12} />
                  <span>Administration</span>
                  <ChevronRight size={12} />
                  <span className="font-semibold">Paramètres</span>
                </div>
              </div>
        
              <div className="chart-card">
                <div className="chart-header mb-20">
                  <h3 className="chart-title">Configuration générale</h3>
                </div>
        
                <div className="space-y-20">
                  <div>
                    <label className="block text-sm mb-8">Plage IP de scan</label>
                    <input
                      type="text"
                      className="form-input"
                      value={settingsData.scan_range}
                      onChange={(e) =>
                        setSettingsData({ ...settingsData, scan_range: e.target.value })
                      }
                    />
                  </div>
        
                  <div>
                    <label className="block text-sm mb-8">Intervalle de scan automatique</label>
                    <select
                      className="form-select"
                      value={settingsData.auto_scan_interval}
                      onChange={(e) =>
                        setSettingsData({ ...settingsData, auto_scan_interval: e.target.value })
                      }
                    >
                      <option>Désactivé</option>
                      <option>5</option>
                      <option>15</option>
                      <option>60</option>
                    </select>
                  </div>
        
                  <div>
                    <label className="block text-sm mb-8">
                      Seuil d’alerte signal faible ({settingsData.signal_threshold}%)
                    </label>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={settingsData.signal_threshold}
                      onChange={(e) =>
                        setSettingsData({
                          ...settingsData,
                          signal_threshold: Number(e.target.value)
                        })
                      }
                      className="w-full"
                    />
                  </div>
        
                  <button className="btn btn-primary" onClick={handleSaveSettings}>
                    Sauvegarder les modifications
                  </button>
                </div>
              </div>
            </div>
          );

          
      case 'users':
        if (currentUser?.role !== 'admin') {
          return (
            <div className="content">
              <div className="text-center py-40">
                <AlertTriangle size={48} className="mx-auto mb-20" />
                <h3>Accès refusé</h3>
                <p>Seul l’administrateur peut accéder à cette page.</p>
                <button className="btn btn-primary mt-20" onClick={() => setActivePage('dashboard')}>
                  <Home size={16} /> Retour au dashboard
                </button>
              </div>
            </div>
          );
        }

        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Gestion des utilisateurs</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Administration</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Utilisateurs</span>
              </div>
            </div>

            <div className="chart-card mb-30">
              <div className="chart-header">
                <h3 className="chart-title">Liste des utilisateurs ({users.length})</h3>
                <button 
                  className="btn btn-primary" 
                  onClick={() => {
                    setEditingUser({
                      id: null,
                      username: '',
                      email: '',
                      full_name: '',
                      role: 'user',
                      is_active: true
                    });
                  }}
                >
                  <Plus size={14} /> Ajouter un utilisateur
                </button>
              </div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Nom</th>
                      <th>Utilisateur</th>
                      <th>Email</th>
                      <th>Rôle</th>
                      <th>Statut</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(user => (
                      <tr key={user.id}>
                        <td>{user.full_name}</td>
                        <td>{user.username}</td>
                        <td className="font-mono">{user.email}</td>
                        <td>
                          <span className="badge badge-info">{user.role}</span>
                        </td>
                        <td>
                          <span className={`badge ${user.is_active ? 'badge-success' : 'badge-danger'}`}>
                            {user.is_active ? 'Actif' : 'Inactif'}
                          </span>
                        </td>
                        <td>
                          <div className="flex gap-10">
                            <button 
                              className="btn btn-secondary" 
                              onClick={() => handleEditUser(user)}
                              title="Modifier"
                            >
                              <Edit size={14} />
                            </button>
                            <button 
                              className="btn btn-secondary" 
                              onClick={() => handleResetPassword(user.id)}
                              title="Réinitialiser le mot de passe"
                            >
                              <Key size={14} />
                            </button>
                            <button 
                              className="btn btn-danger" 
                              onClick={() => handleDeleteUser(user.id)}
                              title="Supprimer"
                            >
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

            {editingUser && (
              <div className="chart-card">
                <div className="chart-header mb-20">
                  <h3 className="chart-title">
                    {editingUser.id ? "Modifier l'utilisateur" : "Ajouter un utilisateur"}
                  </h3>
                  <button 
                    className="btn btn-secondary" 
                    onClick={() => setEditingUser(null)}
                  >
                    Annuler
                  </button>
                </div>
                <div className="space-y-20">
                  <div>
                    <label className="block text-sm mb-8">Nom complet</label>
                    <input
                      type="text"
                      className="form-input"
                      value={editingUser.full_name}
                      onChange={(e) => setEditingUser({...editingUser, full_name: e.target.value})}
                    />
                  </div>
                  <div>
                    <label className="block text-sm mb-8">Nom d'utilisateur</label>
                    <input
                      type="text"
                      className="form-input"
                      value={editingUser.username}
                      onChange={(e) => setEditingUser({...editingUser, username: e.target.value})}
                      disabled={!!editingUser.id}
                    />
                  </div>
                  <div>
                    <label className="block text-sm mb-8">Email</label>
                    <input
                      type="email"
                      className="form-input"
                      value={editingUser.email}
                      onChange={(e) => setEditingUser({...editingUser, email: e.target.value})}
                    />
                  </div>
                  <div>
                    <label className="block text-sm mb-8">Rôle</label>
                    <select
                      className="form-select"
                      value={editingUser.role}
                      onChange={(e) => setEditingUser({...editingUser, role: e.target.value})}
                    >
                      <option value="user">Utilisateur</option>
                      <option value="admin">Administrateur</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm mb-8">Statut</label>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={editingUser.is_active}
                        onChange={(e) => setEditingUser({...editingUser, is_active: e.target.checked})}
                      />
                      <span className="slider"></span>
                    </label>
                    <span className="ml-10">{editingUser.is_active ? 'Actif' : 'Inactif'}</span>
                  </div>
                  {!editingUser.id && (
                    <div>
                      <label className="block text-sm mb-8">Mot de passe</label>
                      <input
                        type="password"
                        className="form-input"
                        onChange={(e) => setEditingUser({...editingUser, password: e.target.value})}
                      />
                    </div>
                  )}
                  <button 
                    className="btn btn-primary" 
                    onClick={handleSaveUser}
                  >
                    {editingUser.id ? "Mettre à jour" : "Créer l'utilisateur"}
                  </button>
                </div>
              </div>
            )}
          </div>
        );

      case 'system':
        const systemInfo = [
          { key: 'Version', value: 'NetMon+ v2.1.0' },
          { key: 'OS', value: 'Ubuntu 22.04 LTS' },
          { key: 'Uptime', value: '15 jours, 7h 22m' },
          { key: 'CPU', value: '4 cœurs / 2.8 GHz' },
          { key: 'Mémoire', value: '16 Go / 12 Go utilisés' },
          { key: 'Disque', value: '500 Go / 320 Go utilisés' },
          { key: 'Base de données', value: 'SQLite' },
        ];

        return (
          <div className="content">
            <div className="page-title mb-30">
              <h1>Système</h1>
              <div className="page-breadcrumb">
                <span>NetMon+</span>
                <ChevronRight size={12} />
                <span>Administration</span>
                <ChevronRight size={12} />
                <span className="font-semibold">Système</span>
              </div>
            </div>

            <div className="chart-card">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Informations système</h3>
                <button className="btn btn-secondary" onClick={refreshCurrentPage}>
                  <RefreshCw size={14} /> Actualiser
                </button>
              </div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Paramètre</th>
                      <th>Valeur</th>
                    </tr>
                  </thead>
                  <tbody>
                    {systemInfo.map((item, index) => (
                      <tr key={index}>
                        <td>{item.key}</td>
                        <td>{item.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="chart-card mt-30">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Maintenance</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-20">
                <button className="btn btn-secondary" onClick={handleBackupDb}>
                  <Download size={14} /> Sauvegarder la base
                </button>
                <button className="btn btn-secondary" onClick={handleCheckUpdates}>
                  <RefreshCw size={14} /> Vérifier les mises à jour
                </button>
                <button className="btn btn-danger" onClick={handleRestartService}>
                  <RotateCcw size={14} /> Redémarrer le service
                </button>
              </div>
            </div>
          </div>
        );

      default:
        return (
          <div className="content">
            <div className="text-center py-40">
              <div className="inline-block p-20 rounded-full mb-20" style={{ 
                background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(139, 92, 246, 0.1))'
              }}>
                <Zap size={40} style={{ color: '#3B82F6' }} />
              </div>
              <h3 className="chart-title mb-10">Fonctionnalité en développement</h3>
              <p className="opacity-75 mb-30">Cette section sera disponible dans la prochaine mise à jour</p>
              <button className="btn btn-primary" onClick={() => setActivePage('dashboard')}>
                <Home size={16} /> Retour au dashboard
              </button>
            </div>
          </div>
        );
    }
  };

  // ======================
  // PAGE DE LOGIN
  // ======================

  if (!isLoggedIn) {
    return (
      <div className={`app-container ${darkMode ? '' : 'light'}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: darkMode ? '#0f172a' : '#f8fafc' }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="chart-card" style={{ width: '100%', maxWidth: '450px', padding: '40px' }}
        >
          <div className="text-center mb-30">
            <div className="inline-block p-20 rounded-full mb-20" style={{ 
              background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(139, 92, 246, 0.1))'
            }}>
              <Wifi size={40} style={{ color: '#3B82F6' }} />
            </div>
            <h2 className="chart-title">NetMon+</h2>
            <p className="opacity-75">Connectez-vous à votre espace sécurisé</p>
          </div>

          {loginError && (
            <div className="alert-item alert-critical mb-20" style={{ padding: '12px' }}>
              {loginError}
            </div>
          )}

          {registerMode ? (
            <form onSubmit={handleRegister}>
              <div className="mb-20">
                <label className="block text-sm mb-8">Nom complet</label>
                <input
                  type="text"
                  className="form-input"
                  value={registerForm.full_name}
                  onChange={(e) => setRegisterForm({...registerForm, full_name: e.target.value})}
                  required
                />
              </div>
              <div className="mb-20">
                <label className="block text-sm mb-8">Nom d’utilisateur</label>
                <input
                  type="text"
                  className="form-input"
                  value={registerForm.username}
                  onChange={(e) => setRegisterForm({...registerForm, username: e.target.value})}
                  required
                />
              </div>
              <div className="mb-20">
                <label className="block text-sm mb-8">Email</label>
                <input
                  type="email"
                  className="form-input"
                  value={registerForm.email}
                  onChange={(e) => setRegisterForm({...registerForm, email: e.target.value})}
                  required
                />
              </div>
              <div className="mb-20">
                <label className="block text-sm mb-8">Mot de passe</label>
                <input
                  type="password"
                  className="form-input"
                  value={registerForm.password}
                  onChange={(e) => setRegisterForm({...registerForm, password: e.target.value})}
                  required
                />
              </div>
              <div className="mb-30">
                <label className="block text-sm mb-8">Confirmer le mot de passe</label>
                <input
                  type="password"
                  className="form-input"
                  value={registerForm.confirm_password}
                  onChange={(e) => setRegisterForm({...registerForm, confirm_password: e.target.value})}
                  required
                />
              </div>
              <button type="submit" className="btn btn-primary w-full">Créer mon compte</button>
              <div className="text-center mt-20">
                <button type="button" onClick={() => setRegisterMode(false)} className="text-sm opacity-75">
                  ← Déjà un compte ? Se connecter
                </button>
              </div>
            </form>
          ) : (
            <form onSubmit={handleLogin}>
              <div className="mb-20">
                <label className="block text-sm mb-8">Nom d’utilisateur</label>
                <input
                  type="text"
                  className="form-input"
                  value={loginForm.username}
                  onChange={(e) => setLoginForm({...loginForm, username: e.target.value})}
                  required
                />
              </div>
              <div className="mb-30">
                <label className="block text-sm mb-8">Mot de passe</label>
                <input
                  type="password"
                  className="form-input"
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                  required
                />
              </div>
              <button type="submit" className="btn btn-primary w-full">Se connecter</button>
              <div className="text-center mt-20">
                <button type="button" onClick={() => setRegisterMode(true)} className="text-sm opacity-75">
                  Pas de compte ? Créer un compte
                </button>
              </div>
            </form>
          )}
        </motion.div>
      </div>
    );
  }

  // ======================
  // INTERFACE PRINCIPALE
  // ======================

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
                        style={{ 
                          display: 'flex',
                          alignItems: 'center',
                          padding: '12px 16px',
                          width: '100%',
                          textAlign: 'left',
                          borderRadius: '8px',
                          transition: 'background 0.2s'
                        }}
                      >
                        <Icon className="menu-icon" size={18} style={{ marginRight: '12px' }} />
                        <span style={{ flex: 1 }}>{item.label}</span>
                        {item.badge && (
                          <span className="menu-badge" style={{ 
                            fontSize: '0.75rem',
                            padding: '2px 6px',
                            borderRadius: '10px'
                          }}>{item.badge}</span>
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="system-status">
            <div className="status-indicator">
              <div className="status-dot"></div>
              <span className="status-text">En ligne</span>
            </div>
            <span className="status-time">{new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </div>
          <button className="logout-btn" onClick={handleLogout} style={{ 
            display: 'flex',
            alignItems: 'center',
            padding: '10px 16px',
            width: '100%',
            background: 'none',
            border: 'none',
            color: '#ef4444',
            cursor: 'pointer',
            fontSize: '0.9rem'
          }}>
            <LogOut size={16} style={{ marginRight: '8px' }}/>
            Déconnexion
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="header">
          <div className="flex items-center">
            <button 
              className="mobile-menu-btn"
              onClick={() => setSidebarOpen(!sidebarOpen)}
            >
              {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
            <div className="page-title">
              <h1>{menuSections.flatMap(s => s.items).find(item => item.id === activePage)?.label || 'Tableau de bord'}</h1>
            </div>
          </div>
          
          <div className="header-actions">
            <button className="notification-bell">
              <Bell size={20} />
              <span className="notification-badge">3</span>
            </button>
            <button 
              className="theme-toggle"
              onClick={() => setDarkMode(!darkMode)}
              title={darkMode ? 'Mode clair' : 'Mode sombre'}
            >
              {darkMode ? <Sun size={20} /> : <Moon size={20} />}
            </button>
          </div>
        </header>

        <AnimatePresence mode="wait">
          <motion.div
            key={activePage}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            {renderPage()}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
};

export default App;