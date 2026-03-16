import React, { useState, useEffect, useCallback, useRef } from 'react';
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
  TrendingUp, TrendingDown,
  FileDown, FileJson, FileSpreadsheet,
  Save
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, AreaChart, Area } from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import './App.css';

// ======================
// DONNÉES SIMULÉES SUPNUM — 10.17.11.0/24
// ======================

const FAKE_DEVICES = [
  { id:1,  name:'GW-SUPNUM',        ip_address:'10.17.11.1',   mac_address:'00:1A:2B:3C:4D:01', vendor:'Cisco Systems',   type:'Router',     status:'Active',  signal_strength:99, is_authorized:true,  is_new:false, first_seen:'2026-01-10T08:00:00', last_seen:'2026-03-16T10:45:00', uptime:'65j 2h' },
  { id:2,  name:'SW-Core-01',       ip_address:'10.17.11.2',   mac_address:'00:1A:2B:3C:4D:02', vendor:'Cisco Systems',   type:'Switch',     status:'Active',  signal_strength:97, is_authorized:true,  is_new:false, first_seen:'2026-01-10T08:00:00', last_seen:'2026-03-16T10:45:00', uptime:'65j 2h' },
  { id:3,  name:'SW-Access-02',     ip_address:'10.17.11.3',   mac_address:'00:1A:2B:3C:4D:03', vendor:'Cisco Systems',   type:'Switch',     status:'Active',  signal_strength:94, is_authorized:true,  is_new:false, first_seen:'2026-01-10T08:00:00', last_seen:'2026-03-16T10:44:00', uptime:'65j 2h' },
  { id:4,  name:'Srv-Web',          ip_address:'10.17.11.10',  mac_address:'08:00:27:AB:CD:10', vendor:'Dell Inc.',       type:'Serveur',    status:'Active',  signal_strength:99, is_authorized:true,  is_new:false, first_seen:'2026-01-15T09:00:00', last_seen:'2026-03-16T10:45:00', uptime:'59j 4h' },
  { id:5,  name:'Srv-DB',           ip_address:'10.17.11.11',  mac_address:'08:00:27:AB:CD:11', vendor:'Dell Inc.',       type:'Serveur',    status:'Active',  signal_strength:99, is_authorized:true,  is_new:false, first_seen:'2026-01-15T09:00:00', last_seen:'2026-03-16T10:43:00', uptime:'59j 4h' },
  { id:6,  name:'Srv-Mail',         ip_address:'10.17.11.12',  mac_address:'08:00:27:AB:CD:12', vendor:'HP Enterprise',   type:'Serveur',    status:'Active',  signal_strength:98, is_authorized:true,  is_new:false, first_seen:'2026-01-15T09:00:00', last_seen:'2026-03-16T10:42:00', uptime:'59j 3h' },
  { id:7,  name:'NAS-Stockage',     ip_address:'10.17.11.15',  mac_address:'00:11:32:DC:EF:15', vendor:'Synology',        type:'NAS',        status:'Active',  signal_strength:92, is_authorized:true,  is_new:false, first_seen:'2026-01-20T10:00:00', last_seen:'2026-03-16T10:40:00', uptime:'55j 0h' },
  { id:8,  name:'Cam-Couloir-01',   ip_address:'10.17.11.20',  mac_address:'00:23:45:67:89:20', vendor:'Hikvision',       type:'Camera',     status:'Active',  signal_strength:78, is_authorized:true,  is_new:false, first_seen:'2026-02-01T08:00:00', last_seen:'2026-03-16T10:44:00', uptime:'43j 0h' },
  { id:9,  name:'Cam-Entree',       ip_address:'10.17.11.21',  mac_address:'00:23:45:67:89:21', vendor:'Hikvision',       type:'Camera',     status:'Active',  signal_strength:82, is_authorized:true,  is_new:false, first_seen:'2026-02-01T08:00:00', last_seen:'2026-03-16T10:44:00', uptime:'43j 0h' },
  { id:10, name:'PC-Lab01-03',      ip_address:'10.17.11.29',  mac_address:'DC:A6:32:42:04:34', vendor:'Hewlett-Packard', type:'PC',         status:'Active',  signal_strength:80, is_authorized:true,  is_new:false, first_seen:'2026-02-10T07:30:00', last_seen:'2026-03-16T10:30:00', uptime:'34j 3h' },
  { id:11, name:'PC-Lab01-12',      ip_address:'10.17.11.46',  mac_address:'54:AB:3A:30:51:C7', vendor:'Hewlett-Packard', type:'PC',         status:'Active',  signal_strength:75, is_authorized:true,  is_new:false, first_seen:'2026-02-10T07:30:00', last_seen:'2026-03-16T10:29:00', uptime:'34j 2h' },
  { id:12, name:'PC-Admin-15',      ip_address:'10.17.11.199', mac_address:'A4:C2:F6:08:E8:04', vendor:'Dell Inc.',       type:'PC',         status:'Active',  signal_strength:88, is_authorized:true,  is_new:false, first_seen:'2026-01-20T08:00:00', last_seen:'2026-03-16T10:45:00', uptime:'55j 2h' },
  { id:13, name:'Laptop-Prof-01',   ip_address:'10.17.11.74',  mac_address:'3C:06:30:14:E1:C4', vendor:'Apple Inc.',      type:'Laptop',     status:'Active',  signal_strength:71, is_authorized:true,  is_new:false, first_seen:'2026-03-10T09:00:00', last_seen:'2026-03-16T10:20:00', uptime:'6j 2h'  },
  { id:14, name:'Laptop-Prof-02',   ip_address:'10.17.11.75',  mac_address:'3C:06:30:14:E1:C5', vendor:'Apple Inc.',      type:'Laptop',     status:'Active',  signal_strength:68, is_authorized:true,  is_new:false, first_seen:'2026-03-10T09:00:00', last_seen:'2026-03-16T10:18:00', uptime:'6j 2h'  },
  { id:15, name:'Phone-Etud-03',    ip_address:'10.17.11.102', mac_address:'B2:45:1F:A3:09:C7', vendor:'Samsung Elec.',   type:'Smartphone', status:'Active',  signal_strength:45, is_authorized:false, is_new:false, first_seen:'2026-03-16T09:00:00', last_seen:'2026-03-16T10:35:00', uptime:'1h 35m' },
  { id:16, name:'Phone-Etud-07',    ip_address:'10.17.11.115', mac_address:'A2:3F:8B:12:45:EE', vendor:'Xiaomi Comm.',    type:'Smartphone', status:'Active',  signal_strength:52, is_authorized:false, is_new:true,  first_seen:'2026-03-16T10:10:00', last_seen:'2026-03-16T10:42:00', uptime:'35m'    },
  { id:17, name:'Phone-Etud-11',    ip_address:'10.17.11.122', mac_address:'C6:7A:2D:F1:88:3B', vendor:'Huawei Device',   type:'Smartphone', status:'Active',  signal_strength:60, is_authorized:false, is_new:false, first_seen:'2026-03-15T08:00:00', last_seen:'2026-03-16T10:38:00', uptime:'1j 2h'  },
  { id:18, name:'Imprimante-HP',    ip_address:'10.17.11.50',  mac_address:'3C:D9:2B:0A:1C:50', vendor:'HP Inc.',         type:'Imprimante', status:'Active',  signal_strength:90, is_authorized:true,  is_new:false, first_seen:'2026-01-15T08:00:00', last_seen:'2026-03-16T09:00:00', uptime:'59j 1h' },
  { id:19, name:'AP-WiFi-Salle3',   ip_address:'10.17.11.33',  mac_address:'F8:32:E4:A1:B2:33', vendor:'Ubiquiti Netw.',  type:'Router',     status:'Active',  signal_strength:95, is_authorized:true,  is_new:false, first_seen:'2026-01-10T08:00:00', last_seen:'2026-03-16T10:45:00', uptime:'65j 0h' },
  { id:20, name:'PC-Lab02-07',      ip_address:'10.17.11.87',  mac_address:'18:60:24:C3:D4:87', vendor:'Lenovo',          type:'PC',         status:'Offline', signal_strength:0,  is_authorized:true,  is_new:false, first_seen:'2026-02-05T07:30:00', last_seen:'2026-03-15T18:00:00', uptime:'—'      },
  { id:21, name:'Laptop-Visiteur',  ip_address:'10.17.11.201', mac_address:'E4:5F:01:AB:CD:EF', vendor:'Unknown',         type:'Laptop',     status:'Offline', signal_strength:0,  is_authorized:false, is_new:true,  first_seen:'2026-03-14T14:00:00', last_seen:'2026-03-14T16:30:00', uptime:'—'      },
  { id:22, name:'IoT-Sensor-01',    ip_address:'10.17.11.60',  mac_address:'AA:BB:CC:DD:EE:60', vendor:'Espressif Inc.',  type:'IoT',        status:'Active',  signal_strength:70, is_authorized:true,  is_new:false, first_seen:'2026-02-20T10:00:00', last_seen:'2026-03-16T10:40:00', uptime:'24j 0h' },
];

const FAKE_ALERTS = [
  { id:1, alert_type:'weak_signal',   message:'Signal faible sur Phone-Etud-03 (45%) — 10.17.11.102', severity:'warning',  timestamp:'2026-03-16T10:35:00', resolved:false, device_ip:'10.17.11.102', device_mac:'B2:45:1F:A3:09:C7', time_ago:'10m' },
  { id:2, alert_type:'new_device',    message:'Nouvel appareil non autorisé : Phone-Etud-07 (Xiaomi) — 10.17.11.115', severity:'warning',  timestamp:'2026-03-16T10:10:00', resolved:false, device_ip:'10.17.11.115', device_mac:'A2:3F:8B:12:45:EE', time_ago:'35m' },
  { id:3, alert_type:'unauthorized',  message:'Appareil non autorisé connecté : Laptop-Visiteur — 10.17.11.201', severity:'critical', timestamp:'2026-03-14T14:00:00', resolved:false, device_ip:'10.17.11.201', device_mac:'E4:5F:01:AB:CD:EF', time_ago:'2j'  },
  { id:4, alert_type:'device_offline',message:'PC-Lab02-07 est hors ligne depuis hier soir — 10.17.11.87',  severity:'warning',  timestamp:'2026-03-15T18:00:00', resolved:false, device_ip:'10.17.11.87',  device_mac:'18:60:24:C3:D4:87', time_ago:'16h' },
  { id:5, alert_type:'scan_complete', message:'Scan terminé sur 10.17.11.0/24 — 20 actifs, 2 hors ligne', severity:'info',     timestamp:'2026-03-16T10:00:00', resolved:true,  device_ip:null, device_mac:null, time_ago:'45m' },
  { id:6, alert_type:'new_device',    message:'Nouvel appareil détecté : IoT-Sensor-01 (Espressif) — 10.17.11.60', severity:'info', timestamp:'2026-02-20T10:00:00', resolved:true, device_ip:'10.17.11.60', device_mac:'AA:BB:CC:DD:EE:60', time_ago:'24j' },
];

const FAKE_STATS = {
  total_devices: 22,
  active_devices: 20,
  inactive_devices: 0,
  offline_devices: 2,
  last_scan: '2026-03-16T10:00:00',
  scanning: false,
};

const FAKE_CHART_DATA = [
  { date:'10/03', active:14, inactive:1, offline:2 },
  { date:'11/03', active:15, inactive:0, offline:2 },
  { date:'12/03', active:16, inactive:1, offline:1 },
  { date:'13/03', active:17, inactive:0, offline:2 },
  { date:'14/03', active:18, inactive:1, offline:2 },
  { date:'15/03', active:19, inactive:0, offline:2 },
  { date:'16/03', active:20, inactive:0, offline:2 },
];

const FAKE_PIE_DATA = [
  { name:'PC',         value:3,  color:'#8B5CF6' },
  { name:'Serveur',    value:3,  color:'#F59E0B' },
  { name:'Router/AP',  value:2,  color:'#3B82F6' },
  { name:'Switch',     value:2,  color:'#06B6D4' },
  { name:'Smartphone', value:3,  color:'#10B981' },
  { name:'Laptop',     value:3,  color:'#8B5CF6' },
  { name:'NAS',        value:1,  color:'#F59E0B' },
  { name:'Caméra',     value:2,  color:'#EF4444' },
  { name:'Imprimante', value:1,  color:'#6B7280' },
  { name:'IoT',        value:1,  color:'#06B6D4' },
  { name:'Inconnu',    value:1,  color:'#374151' },
];

// Scan log steps for animation
const SCAN_STEPS = [
  { msg:'[+] Lancement du scan sur 10.17.11.0/24', prog:5  },
  { msg:'[*] Nmap 7.94 — TCP SYN + ICMP ping', prog:10 },
  { msg:'[*] Envoi des paquets ARP sur le sous-réseau...', prog:15 },
  { msg:'[+] Hôte actif : 10.17.11.1 (0.002s latency)', prog:18 },
  { msg:'[+] Hôte actif : 10.17.11.2 (0.003s latency)', prog:21 },
  { msg:'[+] Hôte actif : 10.17.11.3 (0.003s latency)', prog:24 },
  { msg:'[*] Résolution OUI — 00:1A:2B → Cisco Systems', prog:28 },
  { msg:'[+] Hôte actif : 10.17.11.10 (0.004s latency)', prog:31 },
  { msg:'[+] Hôte actif : 10.17.11.11 (0.004s latency)', prog:34 },
  { msg:'[+] Hôte actif : 10.17.11.12 (0.005s latency)', prog:37 },
  { msg:'[*] Résolution OUI — 08:00:27 → Dell Inc.', prog:40 },
  { msg:'[+] Hôte actif : 10.17.11.15 (0.006s latency)', prog:43 },
  { msg:'[+] Hôte actif : 10.17.11.20 (0.012s latency)', prog:46 },
  { msg:'[*] Port probe TCP : 554,8554 → Camera (Hikvision)', prog:49 },
  { msg:'[+] Hôte actif : 10.17.11.29 (0.008s latency)', prog:52 },
  { msg:'[+] Hôte actif : 10.17.11.33 (0.003s latency)', prog:55 },
  { msg:'[*] Résolution OUI — F8:32:E4 → Ubiquiti Networks', prog:57 },
  { msg:'[+] Hôte actif : 10.17.11.46 (0.009s latency)', prog:60 },
  { msg:'[+] Hôte actif : 10.17.11.50 (0.007s latency)', prog:62 },
  { msg:'[*] Port probe TCP : 9100,515 → Imprimante (HP)', prog:64 },
  { msg:'[+] Hôte actif : 10.17.11.60 (0.014s latency)', prog:66 },
  { msg:'[+] Hôte actif : 10.17.11.74 (0.010s latency)', prog:68 },
  { msg:'[+] Hôte actif : 10.17.11.75 (0.010s latency)', prog:70 },
  { msg:'[+] Hôte actif : 10.17.11.87  — [OFFLINE]', prog:72 },
  { msg:'[+] Hôte actif : 10.17.11.102 (0.025s latency)', prog:74 },
  { msg:'[!] Signal faible détecté : 10.17.11.102 (45%)', prog:76 },
  { msg:'[+] Hôte actif : 10.17.11.115 — MAC aléatoire détectée', prog:78 },
  { msg:'[!] Nouvel appareil non autorisé : 10.17.11.115', prog:80 },
  { msg:'[+] Hôte actif : 10.17.11.122 (0.018s latency)', prog:82 },
  { msg:'[+] Hôte actif : 10.17.11.199 (0.006s latency)', prog:85 },
  { msg:'[+] Hôte actif : 10.17.11.201  — [OFFLINE]', prog:87 },
  { msg:'[*] Interrogation BDD OUI terminée — 22 appareils', prog:90 },
  { msg:'[*] Mise à jour de la base de données SQLite...', prog:93 },
  { msg:'[*] Génération des alertes automatiques...', prog:96 },
  { msg:'[+] Scan terminé — 20 actifs, 2 hors ligne, 2 alertes', prog:100 },
];

// Performance time series data
const genPerfData = () => {
  const d = [];
  for(let i = 0; i < 20; i++) {
    d.push({ t: `${String(Math.floor(i/2+9)).padStart(2,'0')}:${i%2===0?'00':'30'}`, latency: 4+Math.random()*20|0, throughput: 80+Math.random()*120|0 });
  }
  return d;
};

// ======================
// HELPERS
// ======================
const escapePdfText = (t) => String(t).replace(/\\/g,'\\\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)');
const buildSimplePdf = (lines = []) => {
  const header = '%PDF-1.3\n';
  const objects = [];
  objects.push('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
  objects.push('2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n');
  objects.push('3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n');
  objects.push('4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
  const contentLines = ['BT', '/F1 11 Tf', '50 800 Td'];
  lines.slice(0,60).forEach(l => { contentLines.push(`(${escapePdfText(l)}) Tj`); contentLines.push('T*'); });
  contentLines.push('ET');
  const content = contentLines.join('\n') + '\n';
  objects.push(`5 0 obj\n<< /Length ${content.length} >>\nstream\n${content}endstream\nendobj\n`);
  let body = ''; const offsets = [0]; let cursor = header.length;
  for (const obj of objects) { offsets.push(cursor); body += obj; cursor += obj.length; }
  const xrefStart = header.length + body.length;
  let xref = 'xref\n0 6\n0000000000 65535 f \n';
  for (let i=1;i<=5;i++) xref += `${String(offsets[i]).padStart(10,'0')} 00000 n \n`;
  return header + body + xref + `trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
};
const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download=filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
};
const toCsv = (rows) => {
  const esc = v => { const s=String(v??''); return /[,"\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s; };
  if(!rows?.length) return '';
  const headers = Object.keys(rows[0]);
  return [headers.map(esc).join(','), ...rows.map(r=>headers.map(h=>esc(r[h])).join(','))].join('\n');
};

const validateField = (name, value, formData = {}) => {
  switch (name) {
    case 'username': if(!value) return 'Requis'; if(value.length<3) return 'Min 3 caractères'; return null;
    case 'password': if(!value) return 'Requis'; if(value.length<6) return 'Min 6 caractères'; return null;
    case 'email': if(!value) return 'Requis'; if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Email invalide'; return null;
    case 'full_name': if(!value) return 'Requis'; return null;
    case 'register_password': if(!value) return 'Requis'; if(value.length<8) return 'Min 8 caractères'; if(!/[A-Z]/.test(value)) return 'Une majuscule requise'; if(!/[0-9]/.test(value)) return 'Un chiffre requis'; return null;
    case 'confirm_password': if(!value) return 'Requis'; if(value!==formData.password) return 'Mots de passe différents'; return null;
    default: return null;
  }
};

const getPasswordStrength = (password) => {
  const checks = { length:password.length>=8, uppercase:/[A-Z]/.test(password), lowercase:/[a-z]/.test(password), number:/[0-9]/.test(password) };
  const score = Object.values(checks).filter(Boolean).length;
  const percentage = (score/4)*100;
  let color, label;
  if(percentage<=25){color='#ef4444';label='Très faible';}
  else if(percentage<=50){color='#f97316';label='Faible';}
  else if(percentage<=75){color='#eab308';label='Moyen';}
  else{color='#22c55e';label='Fort';}
  return { checks, score, percentage, color, label };
};

const FormField = ({ label,name,type='text',placeholder,icon:Icon,value,onChange,error,hint,rightElement,disabled=false,autoComplete,darkMode }) => (
  <div className="form-field">
    {label && <label className="form-label">{label}</label>}
    <div className="form-input-wrapper">
      {Icon && <span className="form-icon"><Icon size={18}/></span>}
      <input type={type} name={name} placeholder={placeholder} value={value} onChange={onChange} disabled={disabled} autoComplete={autoComplete}
        className={`form-input ${error?'form-input-error':''} ${darkMode?'dark':'light'}`}
        style={{paddingLeft:Icon?'44px':'14px',paddingRight:rightElement?'44px':'14px'}}/>
      {rightElement && <div className="form-right-element">{rightElement}</div>}
    </div>
    {hint&&!error&&<p className="form-hint">{hint}</p>}
    {error&&<p className="form-error"><AlertCircle size={12}/> {error}</p>}
  </div>
);

const PasswordStrengthIndicator = ({ password, darkMode }) => {
  const { checks, percentage, color, label } = getPasswordStrength(password);
  if(!password) return null;
  return (
    <div className="password-strength">
      <div className="password-strength-header"><span>Force</span><span style={{color:percentage===100?'#22c55e':undefined}}>{label}</span></div>
      <div className="password-strength-bar">
        <motion.div className="password-strength-fill" style={{background:color}} initial={{width:0}} animate={{width:`${percentage}%`}} transition={{duration:0.3}}/>
      </div>
      <div className="password-checks">
        {[{label:'8+ chars',valid:checks.length},{label:'Majuscule',valid:checks.uppercase},{label:'Minuscule',valid:checks.lowercase},{label:'Chiffre',valid:checks.number}].map((item,idx)=>(
          <div key={idx} className={`password-check ${item.valid?'valid':''}`}>
            {item.valid?<CheckCircle2 size={12}/>:<AlertCircle size={12}/>}<span>{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ======================
// COMPOSANT PRINCIPAL
// ======================
const App = () => {
  const [darkMode, setDarkMode] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [activePage, setActivePage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Data states — initialized with FAKE data
  const [devices, setDevices] = useState(FAKE_DEVICES);
  const [alerts, setAlerts] = useState(FAKE_ALERTS);
  const [stats, setStats] = useState(FAKE_STATS);
  const [chartData] = useState(FAKE_CHART_DATA);

  // Scan states
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStage, setScanStage] = useState('Prêt');
  const [scanLog, setScanLog] = useState([]);
  const [scanDone, setScanDone] = useState(false);
  const [lastScan, setLastScan] = useState(new Date('2026-03-16T10:00:00'));
  const [lastScanCount, setLastScanCount] = useState(20);

  // UI states
  const [authMode, setAuthMode] = useState('login');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState('');
  const [authSuccess, setAuthSuccess] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loginForm, setLoginForm] = useState({ username:'', password:'', remember:false });
  const [loginErrors, setLoginErrors] = useState({});
  const [registerForm, setRegisterForm] = useState({ username:'', email:'', full_name:'', password:'', confirm_password:'' });
  const [registerErrors, setRegisterErrors] = useState({});
  const [users, setUsers] = useState([
    { id:1, username:'admin',   email:'admin@supnum.mr',   full_name:'Administrateur',        role:'admin', is_active:true },
    { id:2, username:'maty',    email:'maty@supnum.mr',    full_name:'Maty Hadi',              role:'user',  is_active:true },
    { id:3, username:'selme',   email:'selme@supnum.mr',   full_name:'Selme Abdallahi',        role:'user',  is_active:true },
    { id:4, username:'hindou',  email:'hindou@supnum.mr',  full_name:'Hindou Limam',           role:'user',  is_active:true },
    { id:5, username:'noura',   email:'noura@supnum.mr',   full_name:'Noura Salem',            role:'user',  is_active:true },
    { id:6, username:'taghlee', email:'taghlee@supnum.mr', full_name:'Taghle Ely Abeily',      role:'user',  is_active:true },
    { id:7, username:'tourad',  email:'tourad@supnum.mr',  full_name:'Dr. Mamadou Tourad',     role:'admin', is_active:true },
  ]);
  const [editingUser, setEditingUser] = useState(null);
  const [settingsData, setSettingsData] = useState({ ip_range:'10.17.11.0/24', scan_interval:'15 minutes', signal_threshold:30 });
  const [deviceFilter, setDeviceFilter] = useState({ search:'', type:'', status:'' });
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [resolvedAlerts, setResolvedAlerts] = useState(new Set([5,6]));
  const [topoSelected, setTopoSelected] = useState(null);
  const [perfData] = useState(genPerfData());
  const [ipRange, setIpRange] = useState('10.17.11.0/24');
  const scanTimerRef = useRef(null);

  useEffect(() => {
    const handleResize = () => { if(window.innerWidth<992) setSidebarOpen(false); else setSidebarOpen(true); };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // ======================
  // UTILS
  // ======================
  const getDeviceIcon = (type) => {
    switch(type) {
      case 'Laptop': return Monitor; case 'Smartphone': return Smartphone; case 'Router': return Router;
      case 'Serveur': return Server; case 'NAS': return HardDrive; case 'Camera': return Eye;
      case 'Switch': return Network; case 'Firewall': return Shield; default: return Monitor;
    }
  };

  const getTypeColor = (type) => {
    const c = { Router:'#3B82F6', Smartphone:'#10B981', PC:'#8B5CF6', Laptop:'#8B5CF6',
      Serveur:'#F59E0B', NAS:'#F59E0B', Camera:'#EF4444', Imprimante:'#6B7280',
      'Smart TV':'#EC4899', Console:'#EC4899', IoT:'#06B6D4', Switch:'#3B82F6' };
    return c[type] || '#6B7280';
  };

  const StatCard = ({ title, value, change, icon, color='#3B82F6', positive=true }) => (
    <div className="stat-card fade-in">
      <div className="stat-header">
        <div>
          <div className="stat-title">{title}</div>
          <div className="stat-value">{value}</div>
        </div>
        <div className="stat-icon" style={{ background:`${color}20`, color }}>
          {icon}
        </div>
      </div>
      <div className={`stat-change ${positive?'positive':change?.includes?.('↑')?'warning':'negative'}`}>
        <ChevronRight size={14}/> {change}
      </div>
    </div>
  );

  const renderDevicesTable = (showActions=true, filteredList=null) => {
    const list = filteredList || devices;
    return (
      <div className="table-container">
        <table className="data-table">
          <thead><tr>
            <th>Appareil</th><th>IP</th><th>MAC</th><th>Type</th>
            <th>Statut</th><th>Dernière activité</th><th>Signal</th>
            {showActions && <th>Actions</th>}
          </tr></thead>
          <tbody>
            {list.length===0 ? (
              <tr><td colSpan={showActions?8:7} style={{textAlign:'center',padding:'40px',opacity:0.5}}>
                Aucun appareil. Lancez un scan réseau.
              </td></tr>
            ) : list.map(device => {
              const Icon = getDeviceIcon(device.type);
              const color = getTypeColor(device.type);
              const statusBadge = device.status==='Active'?'badge-success':device.status==='Inactive'?'badge-warning':'badge-danger';
              const lastSeen = device.last_seen ? new Date(device.last_seen) : null;
              return (
                <tr key={device.id} className="fade-in" style={{cursor:'pointer'}} onClick={()=>showActions&&setSelectedDevice(device)}>
                  <td>
                    <div className="flex items-center gap-12">
                      <div className="p-8 rounded-lg" style={{backgroundColor:`${color}25`}}>
                        <Icon size={18} color={color}/>
                      </div>
                      <div>
                        <div className="font-medium">{device.name}</div>
                        <div className="text-sm" style={{opacity:0.5,fontSize:'0.78rem'}}>{device.vendor||'Unknown'}</div>
                      </div>
                      {device.is_new && <span className="badge badge-warning" style={{fontSize:'0.7rem'}}>NEW</span>}
                    </div>
                  </td>
                  <td className="font-mono" style={{fontSize:'0.85rem'}}>{device.ip_address}</td>
                  <td className="font-mono" style={{fontSize:'0.78rem',opacity:0.7}}>{device.mac_address}</td>
                  <td><span className="badge" style={{background:`${color}25`,color,border:`1px solid ${color}40`,fontSize:'0.75rem'}}>{device.type}</span></td>
                  <td><span className={`badge ${statusBadge}`}>{device.status==='Active'?'Actif':'Hors ligne'}</span></td>
                  <td style={{fontSize:'0.8rem',opacity:0.7}}>{lastSeen?lastSeen.toLocaleString('fr-FR'):'—'}</td>
                  <td>
                    <div style={{display:'flex',alignItems:'center',gap:'6px'}}>
                      <div style={{width:'50px',height:'6px',background:'rgba(255,255,255,0.1)',borderRadius:'3px',overflow:'hidden'}}>
                        <div style={{width:`${device.signal_strength||0}%`,height:'100%',background:device.signal_strength>70?'#10B981':device.signal_strength>40?'#F59E0B':'#EF4444',borderRadius:'3px'}}/>
                      </div>
                      <span style={{fontSize:'0.78rem',fontFamily:'monospace'}}>{device.signal_strength||0}%</span>
                    </div>
                  </td>
                  {showActions && (
                    <td onClick={e=>e.stopPropagation()}>
                      <button className="btn btn-secondary" style={{padding:'5px 10px',fontSize:'0.8rem'}} onClick={()=>setSelectedDevice(device)}>Détails</button>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  };

  // ======================
  // AUTHENTIFICATION (DEMO)
  // ======================
  const handleLoginChange = (e) => {
    const { name, value, type, checked } = e.target;
    setLoginForm(prev => ({...prev, [name]: type==='checkbox'?checked:value}));
    if(loginErrors[name]) setLoginErrors(prev=>({...prev,[name]:null}));
  };

  const handleLogin = async (e) => {
    if(e) e.preventDefault();
    const errors = {};
    const uE = validateField('username', loginForm.username);
    const pE = validateField('password', loginForm.password);
    if(uE) errors.username = uE;
    if(pE) errors.password = pE;
    if(Object.keys(errors).length>0) { setLoginErrors(errors); return; }
    setAuthError(''); setAuthLoading(true);
    await new Promise(r=>setTimeout(r,800));
    // Accept any credentials for demo — admin/admin123 is default
    setIsLoggedIn(true);
    setCurrentUser({ id:1, username:loginForm.username||'admin', role:loginForm.username==='tourad'?'admin':'admin' });
    setActivePage('dashboard');
    setAuthSuccess('Connexion réussie !');
    setAuthLoading(false);
  };

  const handleRegisterChange = (e) => {
    const { name, value } = e.target;
    setRegisterForm(prev=>({...prev,[name]:value}));
    if(registerErrors[name]) setRegisterErrors(prev=>({...prev,[name]:null}));
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    const errors = {};
    ['full_name','username','email'].forEach(f=>{ const err=validateField(f,registerForm[f]); if(err) errors[f]=err; });
    const pE=validateField('register_password',registerForm.password); if(pE) errors.password=pE;
    const cE=validateField('confirm_password',registerForm.confirm_password,registerForm); if(cE) errors.confirm_password=cE;
    if(Object.keys(errors).length>0){setRegisterErrors(errors);return;}
    setAuthLoading(true);
    await new Promise(r=>setTimeout(r,800));
    setAuthSuccess('Compte créé avec succès !');
    setTimeout(()=>{setAuthMode('login');setAuthSuccess('');setRegisterForm({username:'',email:'',full_name:'',password:'',confirm_password:''});},2000);
    setAuthLoading(false);
  };

  const handleLogout = () => {
    setIsLoggedIn(false); setCurrentUser(null); setActivePage('dashboard');
    setAuthMode('login'); setLoginForm({username:'',password:'',remember:false});
    setAuthError(''); setAuthSuccess('');
  };

  // ======================
  // SCAN SIMULÉ
  // ======================
  const startScan = async () => {
    if(scanning) return;
    setScanning(true); setScanDone(false); setScanProgress(0);
    setScanStage('Initialisation...'); setScanLog([`[+] Démarrage du scan sur ${ipRange}`]);

    let step = 0;
    const interval = setInterval(() => {
      if(step >= SCAN_STEPS.length) {
        clearInterval(interval);
        setScanning(false); setScanDone(true);
        setScanStage('Terminé'); setScanProgress(100);
        setLastScan(new Date()); setLastScanCount(20);
        setDevices(FAKE_DEVICES);
        setAlerts(FAKE_ALERTS);
        setStats({...FAKE_STATS, last_scan: new Date().toISOString()});
        return;
      }
      const s = SCAN_STEPS[step];
      setScanLog(prev => [...prev.slice(-25), s.msg]);
      setScanProgress(s.prog);
      setScanStage(s.msg.replace(/^\[.\] /,'').substring(0,40)+'...');
      step++;
    }, 180);
    scanTimerRef.current = interval;
  };

  // ======================
  // ACTIONS
  // ======================
  const handleGenerateReport = () => {
    const lines = [
      'NetMon+ — Rapport de surveillance réseau',
      `Institut Supérieur du Numérique SUPNUM`,
      `Généré le: ${new Date().toLocaleString('fr-FR')}`,
      `Par: ${currentUser?.username}`,
      '=========================================',
      `Réseau scanné: 10.17.11.0/24`,
      `Équipements totaux: ${stats.total_devices}`,
      `Actifs: ${stats.active_devices}`,
      `Hors ligne: ${stats.offline_devices}`,
      '=========================================',
      'Inventaire des équipements:',
      ...FAKE_DEVICES.map((d,i)=>`${i+1}. ${d.name} | ${d.ip_address} | ${d.type} | ${d.status}`),
      '=========================================',
      'Alertes actives:',
      ...FAKE_ALERTS.filter(a=>!a.resolved).map(a=>`[${a.severity.toUpperCase()}] ${a.message}`),
      '=========================================',
      'Fin du rapport — NetMon+ v1.0.0',
    ];
    const pdf = buildSimplePdf(lines);
    downloadBlob(new Blob([pdf],{type:'application/pdf'}), `rapport_netmon_supnum_${Date.now()}.pdf`);
  };

  const handleExport = (type, format) => {
    if(format==='csv') {
      const data = type==='devices' ? FAKE_DEVICES.map(d=>({Nom:d.name,IP:d.ip_address,MAC:d.mac_address,Type:d.type,Statut:d.status,Signal:d.signal_strength+'%',Vendor:d.vendor}))
        : FAKE_ALERTS.map(a=>({Type:a.alert_type,Message:a.message,Severite:a.severity,IP:a.device_ip||'',Timestamp:a.timestamp,Resolu:a.resolved?'Oui':'Non'}));
      downloadBlob(new Blob([toCsv(data)],{type:'text/csv'}), `${type}_supnum.csv`);
    } else {
      const data = type==='devices' ? FAKE_DEVICES : type==='alerts' ? FAKE_ALERTS : FAKE_ALERTS;
      downloadBlob(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}), `${type}_supnum.json`);
    }
  };

  const handleSaveUser = () => {
    if(editingUser) {
      setUsers(prev=>prev.map(u=>u.id===editingUser.id?editingUser:u));
      setEditingUser(null);
    }
  };

  const handleSaveSettings = () => { alert('Paramètres sauvegardés !'); };

  const refreshCurrentPage = () => {
    setDevices([...FAKE_DEVICES]);
    setAlerts([...FAKE_ALERTS]);
    setStats({...FAKE_STATS});
  };

  // ======================
  // MENU
  // ======================
  const menuSections = (() => {
    const base = [
      { title:'PRINCIPAL', items:[
        { id:'dashboard', label:'Tableau de bord', icon:Home, badge:null },
        { id:'scan', label:'Scan Réseau', icon:Search, badge:null },
      ]},
      { title:'SURVEILLANCE', items:[
        { id:'devices', label:'Équipements', icon:Network, badge:devices.length },
        { id:'topology', label:'Topologie', icon:CircuitBoard, badge:null },
        { id:'performance', label:'Performance', icon:Activity, badge:null },
      ]},
      { title:'SÉCURITÉ', items:[
        { id:'alerts', label:'Alertes', icon:Bell, badge:alerts.filter(a=>!a.resolved&&!resolvedAlerts.has(a.id)).length||null },
        { id:'firewall', label:'Firewall', icon:Shield, badge:null },
        { id:'logs', label:'Logs & Audit', icon:History, badge:null },
      ]},
      { title:'RAPPORTS', items:[
        { id:'reports', label:'Rapports', icon:FileText, badge:null },
        { id:'statistics', label:'Statistiques', icon:BarChart3, badge:null },
        { id:'exports', label:'Exports', icon:Download, badge:null },
      ]},
    ];
    if(currentUser?.role==='admin') {
      base.push({ title:'ADMINISTRATION', items:[
        { id:'settings', label:'Paramètres', icon:Settings, badge:null },
        { id:'users', label:'Utilisateurs', icon:User, badge:null },
        { id:'system', label:'Système', icon:Server, badge:null },
      ]});
    }
    return base;
  })();

  // ======================
  // AUTH PAGE
  // ======================
  const renderAuthPage = () => {
    const togglePasswordBtn = (
      <button type="button" onClick={()=>setShowPassword(!showPassword)} className="password-toggle-btn">
        {showPassword?<EyeOff size={18}/>:<Eye size={18}/>}
      </button>
    );
    const toggleConfirmPasswordBtn = (
      <button type="button" onClick={()=>setShowConfirmPassword(!showConfirmPassword)} className="password-toggle-btn">
        {showConfirmPassword?<EyeOff size={18}/>:<Eye size={18}/>}
      </button>
    );
    return (
      <div className={`auth-page ${darkMode?'dark':'light'}`}>
        <div className="auth-branding">
          <div className="auth-decoration-circle auth-decoration-1"/>
          <div className="auth-decoration-circle auth-decoration-2"/>
          <div className="auth-branding-content">
            <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{duration:0.5}}>
              <div className="auth-branding-logo"><Wifi size={40} color="white"/></div>
              <h1 style={{fontSize:'2.5rem',fontWeight:700,marginBottom:'16px'}}>NetMon+</h1>
              <p style={{fontSize:'1.25rem',opacity:0.8,marginBottom:'40px'}}>Network Monitor Pro</p>
              <div style={{textAlign:'left',maxWidth:'400px'}}>
                {[{icon:Shield,text:'Surveillance réseau en temps réel'},{icon:Wifi,text:'Détection automatique des appareils'},{icon:CheckCircle2,text:'Alertes de sécurité intelligentes'}].map((item,index)=>(
                  <motion.div key={index} initial={{opacity:0,x:-20}} animate={{opacity:1,x:0}} transition={{delay:0.2+index*0.1,duration:0.3}} className="auth-feature">
                    <div className="auth-feature-icon"><item.icon size={20}/></div>
                    <span style={{opacity:0.9}}>{item.text}</span>
                  </motion.div>
                ))}
              </div>
            </motion.div>
            <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:0.5,duration:0.3}} className="auth-stats">
              {[{value:'10K+',label:'Utilisateurs'},{value:'99.9%',label:'Uptime'},{value:'24/7',label:'Support'}].map((stat,index)=>(
                <div key={index} className="auth-stat">
                  <div style={{fontSize:'1.5rem',fontWeight:700}}>{stat.value}</div>
                  <div style={{fontSize:'0.875rem',opacity:0.6}}>{stat.label}</div>
                </div>
              ))}
            </motion.div>
          </div>
        </div>
        <div className="auth-form-panel">
          <div className="auth-form-container">
            <AnimatePresence mode="wait">
              {authMode==='login' && (
                <motion.div key="login" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} transition={{duration:0.2}}>
                  <div className="auth-mobile-logo">
                    <div className="auth-mobile-logo-icon"><Wifi size={32} color="white"/></div>
                    <h2 className="auth-title">Bon retour !</h2>
                    <p className="auth-subtitle">Connectez-vous à NetMon+ SUPNUM</p>
                  </div>
                  <div className={`auth-card ${darkMode?'dark':'light'}`}>
                    {authError&&<div className="auth-alert auth-alert-error"><AlertCircle size={18}/><span>{authError}</span></div>}
                    {authSuccess&&<div className="auth-alert auth-alert-success"><CheckCircle2 size={18}/><span>{authSuccess}</span></div>}
                    <form onSubmit={handleLogin}>
                      <FormField label="Nom d'utilisateur" name="username" placeholder="admin" icon={User} value={loginForm.username} onChange={handleLoginChange} error={loginErrors.username} autoComplete="username" darkMode={darkMode}/>
                      <FormField label="Mot de passe" name="password" type={showPassword?'text':'password'} placeholder="••••••••" icon={Lock} value={loginForm.password} onChange={handleLoginChange} error={loginErrors.password} rightElement={togglePasswordBtn} autoComplete="current-password" darkMode={darkMode}/>
                      <div className="auth-options">
                        <label className="auth-checkbox">
                          <input type="checkbox" name="remember" checked={loginForm.remember} onChange={handleLoginChange}/>
                          <span>Se souvenir de moi</span>
                        </label>
                      </div>
                      <button type="submit" disabled={authLoading} className="auth-submit-btn">
                        {authLoading?(<><Loader2 size={18} className="animate-spin"/>Connexion...</>):(<>Se connecter<ArrowRight size={18}/></>)}
                      </button>
                    </form>
                  </div>
                  <p className="auth-switch">Pas de compte ? <button onClick={()=>{setAuthMode('register');setAuthError('');setAuthSuccess('');}} className="auth-switch-link">Créer un compte</button></p>
                </motion.div>
              )}
              {authMode==='register' && (
                <motion.div key="register" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} transition={{duration:0.2}}>
                  <div className="auth-mobile-logo">
                    <div className="auth-mobile-logo-icon"><Wifi size={32} color="white"/></div>
                    <h2 className="auth-title">Créer un compte</h2>
                    <p className="auth-subtitle">Rejoignez NetMon+ SUPNUM</p>
                  </div>
                  <div className={`auth-card ${darkMode?'dark':'light'}`}>
                    {authError&&<div className="auth-alert auth-alert-error"><AlertCircle size={18}/><span>{authError}</span></div>}
                    {authSuccess&&<div className="auth-alert auth-alert-success"><CheckCircle2 size={18}/><span>{authSuccess}</span></div>}
                    <form onSubmit={handleRegister}>
                      <FormField label="Nom complet" name="full_name" placeholder="Votre nom" icon={User} value={registerForm.full_name} onChange={handleRegisterChange} error={registerErrors.full_name} autoComplete="name" darkMode={darkMode}/>
                      <FormField label="Nom d'utilisateur" name="username" placeholder="ex: johndoe" icon={User} value={registerForm.username} onChange={handleRegisterChange} error={registerErrors.username} autoComplete="username" darkMode={darkMode}/>
                      <FormField label="Email" name="email" type="email" placeholder="nom@supnum.mr" icon={Mail} value={registerForm.email} onChange={handleRegisterChange} error={registerErrors.email} autoComplete="email" darkMode={darkMode}/>
                      <div>
                        <FormField label="Mot de passe" name="password" type={showPassword?'text':'password'} placeholder="••••••••" icon={Lock} value={registerForm.password} onChange={handleRegisterChange} error={registerErrors.password} rightElement={togglePasswordBtn} autoComplete="new-password" darkMode={darkMode}/>
                        <PasswordStrengthIndicator password={registerForm.password} darkMode={darkMode}/>
                      </div>
                      <div style={{marginTop:'20px'}}>
                        <FormField label="Confirmer" name="confirm_password" type={showConfirmPassword?'text':'password'} placeholder="••••••••" icon={Lock} value={registerForm.confirm_password} onChange={handleRegisterChange} error={registerErrors.confirm_password} rightElement={toggleConfirmPasswordBtn} autoComplete="new-password" darkMode={darkMode}/>
                      </div>
                      <button type="submit" disabled={authLoading} className="auth-submit-btn" style={{marginTop:'24px'}}>
                        {authLoading?(<><Loader2 size={18} className="animate-spin"/>Création...</>):(<>Créer mon compte<ArrowRight size={18}/></>)}
                      </button>
                    </form>
                  </div>
                  <p className="auth-switch">Déjà un compte ? <button onClick={()=>{setAuthMode('login');setAuthError('');setAuthSuccess('');}} className="auth-switch-link">Se connecter</button></p>
                </motion.div>
              )}
            </AnimatePresence>
            <p className="auth-footer">NetMon+ — Projet Intégrateur S3 · SUPNUM 2026</p>
          </div>
        </div>
      </div>
    );
  };

  // ======================
  // PAGES
  // ======================
  const renderDashboard = () => {
    const activeDevices = devices.filter(d=>d.status==='Active').length;
    const offlineDevices = devices.filter(d=>d.status==='Offline').length;
    const openAlerts = alerts.filter(a=>!a.resolved&&!resolvedAlerts.has(a.id)).length;
    const typeMap = {};
    devices.forEach(d=>{ typeMap[d.type]=(typeMap[d.type]||0)+1; });
    const pieData = Object.entries(typeMap).map(([name,value])=>({ name, value, color:getTypeColor(name) }));

    return (
      <div className="content">
        <div className="page-title mb-30">
          <h1>Tableau de bord</h1>
          <div className="page-breadcrumb">
            <span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Dashboard</span>
          </div>
        </div>

        {devices.length===0 ? (
          <div style={{textAlign:'center',padding:'80px',opacity:0.5}}>
            <Network size={64} style={{marginBottom:'16px'}}/>
            <h3>Aucun scan effectué</h3>
            <p style={{marginTop:'8px'}}>Lancez un scan réseau pour afficher le tableau de bord.</p>
            <button className="btn btn-primary" style={{marginTop:'20px'}} onClick={()=>setActivePage('scan')}>
              <Search size={16}/> Lancer un scan
            </button>
          </div>
        ) : (
          <>
            <div className="stats-grid">
              <StatCard title="Équipements totaux" value={devices.length} change={`Réseau ${ipRange}`} icon={<Users size={24}/>}/>
              <StatCard title="Actifs" value={activeDevices} change="Connectés" icon={<WifiHigh size={24}/>} color="#10B981"/>
              <StatCard title="Hors ligne" value={offlineDevices} change="À vérifier" icon={<WifiOff size={24}/>} color="#EF4444" positive={false}/>
              <StatCard title="Alertes ouvertes" value={openAlerts} change="Non résolues" icon={<Bell size={24}/>} color="#F59E0B" positive={openAlerts===0}/>
            </div>
            <div className="charts-grid">
              <div className="chart-card fade-in">
                <div className="chart-header"><h3 className="chart-title">Activité réseau (7 jours)</h3></div>
                <ResponsiveContainer width="100%" height={280}>
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode?'#334155':'#e2e8f0'}/>
                    <XAxis dataKey="date" stroke={darkMode?'#94a3b8':'#64748b'}/>
                    <YAxis stroke={darkMode?'#94a3b8':'#64748b'}/>
                    <Tooltip contentStyle={{backgroundColor:darkMode?'#1e293b':'#ffffff',borderRadius:'8px'}}/>
                    <Legend/>
                    <Line type="monotone" dataKey="active" stroke="#10B981" name="Actifs" strokeWidth={2} dot={false}/>
                    <Line type="monotone" dataKey="offline" stroke="#EF4444" name="Hors ligne" strokeWidth={2} dot={false}/>
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <div className="chart-card fade-in">
                <div className="chart-header"><h3 className="chart-title">Répartition par type</h3></div>
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} label={({name,percent})=>`${name} ${(percent*100).toFixed(0)}%`}>
                      {pieData.map((entry,index)=><Cell key={index} fill={entry.color}/>)}
                    </Pie>
                    <Tooltip contentStyle={{backgroundColor:darkMode?'#1e293b':'#ffffff',borderRadius:'8px'}}/>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="chart-card fade-in">
              <div className="chart-header mb-20">
                <h3 className="chart-title">Dernier scan</h3>
                <span style={{fontSize:'0.8rem',opacity:0.5}}>{lastScan?.toLocaleString('fr-FR')}</span>
              </div>
              <div style={{display:'flex',alignItems:'center',gap:'20px',flexWrap:'wrap'}}>
                <div style={{background:'rgba(16,185,129,0.1)',border:'1px solid rgba(16,185,129,0.3)',borderRadius:'8px',padding:'12px 20px',display:'flex',alignItems:'center',gap:'10px'}}>
                  <CheckCircle2 size={20} color="#10B981"/>
                  <span>Scan terminé — <strong>{lastScanCount}</strong> appareils actifs détectés</span>
                </div>
                <div style={{fontSize:'0.85rem',opacity:0.6}}>Plage : <code>{ipRange}</code></div>
                <button className="btn btn-primary" onClick={()=>setActivePage('scan')}><Search size={14}/> Nouveau scan</button>
              </div>
            </div>
          </>
        )}
      </div>
    );
  };

  const renderScan = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Scan Réseau</h1>
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Scan</span></div>
      </div>
      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title"><Search size={20} style={{marginRight:'8px'}}/>Configurer et lancer le scan</h3>
        </div>
        <div className="scan-controls">
          <div className="form-group">
            <label>Plage IP à scanner</label>
            <input type="text" className="form-control" value={ipRange} onChange={e=>setIpRange(e.target.value)} placeholder="10.17.11.0/24"/>
            <small style={{opacity:0.5,fontSize:'0.8rem',marginTop:'4px',display:'block'}}>Exemple : 10.17.11.0/24 (réseau SUPNUM)</small>
          </div>
          <button onClick={startScan} disabled={scanning} className="btn btn-primary">
            {scanning?(<><RefreshCw className="animate-spin" size={16}/> Scan en cours...</>):(<><Search size={16}/> Lancer le scan</>)}
          </button>
        </div>
        {(scanning || scanDone) && (
          <div className="scan-progress">
            <div className="progress-header">
              <span style={{fontSize:'0.85rem',fontFamily:'monospace'}}>{scanStage}</span>
              <span style={{fontWeight:600}}>{scanProgress}%</span>
            </div>
            <div className="progress-bar">
              <div className="progress-fill" style={{width:`${scanProgress}%`,transition:'width 0.2s ease'}}/>
            </div>
            <div className="scan-log" style={{maxHeight:'220px',overflowY:'auto'}}>
              {scanLog.map((line,i)=>(
                <div key={i} className="log-line" style={{color:line.includes('[!]')?'#F59E0B':line.includes('[+]')?'#10B981':'rgba(255,255,255,0.6)',fontSize:'0.82rem',fontFamily:'monospace',padding:'1px 0'}}>
                  {line}
                </div>
              ))}
            </div>
          </div>
        )}
        {!scanning && scanDone && (
          <div className="scan-results" style={{marginTop:'16px'}}>
            <div className="success-message" style={{display:'flex',alignItems:'center',gap:'10px',background:'rgba(16,185,129,0.1)',border:'1px solid rgba(16,185,129,0.3)',borderRadius:'8px',padding:'12px 16px'}}>
              <CheckCircle2 size={20} color="#10B981"/>
              <span>Scan terminé — <strong>20 appareils actifs</strong>, 2 hors ligne détectés sur {ipRange}</span>
            </div>
            <div style={{display:'flex',gap:'12px',marginTop:'12px'}}>
              <button className="btn btn-secondary" onClick={()=>setActivePage('devices')}><Network size={14}/> Voir les équipements</button>
              <button className="btn btn-secondary" onClick={()=>setActivePage('alerts')}><Bell size={14}/> Voir les alertes</button>
              <button className="btn btn-secondary" onClick={()=>setActivePage('topology')}><CircuitBoard size={14}/> Topologie</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  const renderDevices = () => {
    const deviceTypes = [...new Set(devices.map(d=>d.type).filter(Boolean))];
    const filtered = devices.filter(d=>{
      const q = deviceFilter.search.toLowerCase();
      const matchSearch = !q||(d.name||'').toLowerCase().includes(q)||(d.ip_address||'').includes(q)||(d.mac_address||'').toLowerCase().includes(q)||(d.vendor||'').toLowerCase().includes(q);
      const matchType = !deviceFilter.type||d.type===deviceFilter.type;
      const matchStatus = !deviceFilter.status||d.status===deviceFilter.status;
      return matchSearch&&matchType&&matchStatus;
    });
    return (
      <div className="content">
        <div className="page-title mb-30">
          <h1>Équipements</h1>
          <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Devices</span></div>
        </div>
        <div className="stats-grid" style={{gridTemplateColumns:'repeat(4,1fr)',marginBottom:'20px'}}>
          {[{label:'Total',val:devices.length,color:'#3B82F6'},{label:'Actifs',val:devices.filter(d=>d.status==='Active').length,color:'#10B981'},{label:'Hors ligne',val:devices.filter(d=>d.status==='Offline').length,color:'#EF4444'},{label:'Types',val:deviceTypes.length,color:'#8B5CF6'}].map((s,i)=>(
            <div key={i} className="stat-card fade-in" style={{padding:'16px'}}>
              <div style={{fontSize:'1.8rem',fontWeight:700,color:s.color}}>{s.val}</div>
              <div style={{fontSize:'0.85rem',opacity:0.6,marginTop:'2px'}}>{s.label}</div>
            </div>
          ))}
        </div>
        <div className="chart-card fade-in">
          <div className="chart-header mb-20">
            <h3 className="chart-title">Liste des équipements ({filtered.length})</h3>
            <div className="header-actions">
              <button className="btn btn-secondary" onClick={refreshCurrentPage}><RefreshCw size={14}/> Actualiser</button>
              <button className="btn btn-primary" onClick={startScan} disabled={scanning}><Search size={14}/> {scanning?'Scan...':'Scanner'}</button>
            </div>
          </div>
          <div className="filters-bar">
            <div className="search-input">
              <Search size={16}/>
              <input type="text" placeholder="Nom, IP, MAC, vendor..." value={deviceFilter.search} onChange={e=>setDeviceFilter(f=>({...f,search:e.target.value}))}/>
            </div>
            <select className="form-control" style={{width:'auto'}} value={deviceFilter.type} onChange={e=>setDeviceFilter(f=>({...f,type:e.target.value}))}>
              <option value="">Tous les types</option>
              {deviceTypes.map(t=><option key={t} value={t}>{t}</option>)}
            </select>
            <select className="form-control" style={{width:'auto'}} value={deviceFilter.status} onChange={e=>setDeviceFilter(f=>({...f,status:e.target.value}))}>
              <option value="">Tous les statuts</option>
              <option value="Active">Actif</option>
              <option value="Offline">Hors ligne</option>
            </select>
            {(deviceFilter.search||deviceFilter.type||deviceFilter.status)&&(
              <button className="btn btn-secondary" onClick={()=>setDeviceFilter({search:'',type:'',status:''})}><X size={14}/> Effacer</button>
            )}
          </div>
          {renderDevicesTable(true, filtered)}
        </div>
        {selectedDevice&&(
          <div className="modal-overlay" onClick={()=>setSelectedDevice(null)}>
            <div className="modal" onClick={e=>e.stopPropagation()} style={{maxWidth:'480px'}}>
              <div className="modal-header">
                <h3 style={{display:'flex',alignItems:'center',gap:'10px'}}>
                  {React.createElement(getDeviceIcon(selectedDevice.type),{size:20})} {selectedDevice.name}
                </h3>
                <button className="modal-close" onClick={()=>setSelectedDevice(null)}><X size={20}/></button>
              </div>
              <div className="modal-body">
                {[['IP',selectedDevice.ip_address],['MAC',selectedDevice.mac_address],['Type',selectedDevice.type],['Vendor',selectedDevice.vendor],['Statut',selectedDevice.status],['Signal',`${selectedDevice.signal_strength||0}%`],['Uptime',selectedDevice.uptime||'—'],['Première détection',selectedDevice.first_seen?new Date(selectedDevice.first_seen).toLocaleString('fr-FR'):'—'],['Dernière activité',selectedDevice.last_seen?new Date(selectedDevice.last_seen).toLocaleString('fr-FR'):'—'],['Autorisé',selectedDevice.is_authorized?'Oui':'Non']].map(([k,v])=>(
                  <div key={k} className="info-row">
                    <span className="info-label">{k}</span>
                    <span className="info-value font-mono" style={{fontSize:'0.85rem'}}>{v||'—'}</span>
                  </div>
                ))}
              </div>
              <div className="modal-footer">
                <button className="btn btn-secondary" onClick={()=>setSelectedDevice(null)}>Fermer</button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderAlerts = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Alertes</h1>
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Alerts</span></div>
      </div>
      <div className="stats-grid" style={{gridTemplateColumns:'repeat(3,1fr)'}}>
        <StatCard title="Alertes critiques" value={alerts.filter(a=>a.severity==='critical').length} change="À traiter" icon={<AlertOctagon size={24}/>} color="#EF4444" positive={false}/>
        <StatCard title="Avertissements" value={alerts.filter(a=>a.severity==='warning').length} change="En attente" icon={<AlertTriangle size={24}/>} color="#F59E0B" positive={false}/>
        <StatCard title="Informations" value={alerts.filter(a=>a.severity==='info').length} change="Consultées" icon={<Info size={24}/>} color="#3B82F6"/>
      </div>
      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Alertes récentes</h3>
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={refreshCurrentPage}><RefreshCw size={14}/> Actualiser</button>
            <button className="btn btn-secondary" onClick={()=>setResolvedAlerts(new Set(alerts.map(a=>a.id)))}><CheckCircle size={14}/> Tout résoudre</button>
          </div>
        </div>
        <div className="alerts-list">
          {alerts.length===0?(
            <div className="text-center" style={{padding:'40px',opacity:0.6}}>
              <Bell size={32} style={{marginBottom:'12px'}}/><p>Aucune alerte</p>
            </div>
          ):alerts.map(alert=>{
            const isResolved = alert.resolved||resolvedAlerts.has(alert.id);
            return (
              <div key={alert.id} className={`alert-item alert-${alert.severity}`} style={{opacity:isResolved?0.5:1}}>
                <div className="alert-icon">
                  {alert.severity==='critical'?<AlertOctagon size={20}/>:alert.severity==='warning'?<AlertTriangle size={20}/>:<Info size={20}/>}
                </div>
                <div className="alert-content">
                  <div className="alert-message">{alert.message}</div>
                  <div className="alert-meta">
                    <span className="alert-type">{alert.alert_type}</span>
                    <span className="alert-time">{alert.time_ago}</span>
                  </div>
                </div>
                <div className="alert-actions">
                  {alert.device_ip&&<button className="btn btn-sm btn-secondary" onClick={()=>{setActivePage('devices');setDeviceFilter({search:alert.device_ip,type:'',status:''});}}><EyeIcon size={14}/></button>}
                  <button className="btn btn-sm btn-secondary" style={isResolved?{opacity:0.4}:{}} onClick={()=>setResolvedAlerts(prev=>new Set([...prev,alert.id]))}><CheckCircle size={14}/></button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );

  const renderTopology = () => {
    const router = devices.find(d=>d.type==='Router')||{id:0,name:'GW-SUPNUM',ip_address:'10.17.11.1',status:'Active',type:'Router',mac_address:'00:1A:2B:3C:4D:01',vendor:'Cisco',signal_strength:99};
    const clients = devices.filter(d=>d.type!=='Router');
    const W=900,H=540,CX=W/2,CY=H/2;
    const R=Math.min(210,80+clients.length*15);
    const typeColors={Router:'#3B82F6',Smartphone:'#10B981',PC:'#8B5CF6',Laptop:'#8B5CF6',Serveur:'#F59E0B',NAS:'#F59E0B',Camera:'#EF4444',Imprimante:'#6B7280','Smart TV':'#EC4899',Console:'#EC4899',IoT:'#06B6D4',Switch:'#3B82F6',Unknown:'#6B7280'};
    return (
      <div className="content">
        <div className="page-title mb-30">
          <h1>Topologie Réseau</h1>
          <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Topology</span></div>
        </div>
        <div className="stats-grid" style={{gridTemplateColumns:'repeat(4,1fr)',marginBottom:'20px'}}>
          {[{label:'Appareils',val:devices.length,color:'#3B82F6'},{label:'En ligne',val:devices.filter(d=>d.status==='Active').length,color:'#10B981'},{label:'Hors ligne',val:devices.filter(d=>d.status==='Offline').length,color:'#EF4444'},{label:'Types',val:[...new Set(devices.map(d=>d.type))].length,color:'#8B5CF6'}].map((s,i)=>(
            <div key={i} className="stat-card fade-in" style={{padding:'16px'}}>
              <div style={{fontSize:'1.8rem',fontWeight:700,color:s.color}}>{s.val}</div>
              <div style={{fontSize:'0.85rem',opacity:0.6}}>{s.label}</div>
            </div>
          ))}
        </div>
        <div className="chart-card fade-in" style={{padding:0,overflow:'hidden'}}>
          <div className="chart-header mb-0" style={{padding:'20px 24px',borderBottom:'1px solid rgba(255,255,255,0.06)'}}>
            <h3 className="chart-title">Carte réseau — {ipRange}</h3>
            <div className="header-actions">
              <span style={{fontSize:'0.8rem',opacity:0.5}}>{devices.length} appareils · Cliquer pour détails</span>
              <button className="btn btn-secondary" onClick={refreshCurrentPage}><RefreshCw size={14}/> Actualiser</button>
            </div>
          </div>
          <div style={{display:'flex',height:'560px'}}>
            <svg width="100%" height="100%" viewBox={`0 0 ${W} ${H}`} style={{flex:1,background:'transparent'}}>
              <defs>
                <radialGradient id="bgGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#1e3a5f" stopOpacity="0.3"/>
                  <stop offset="100%" stopColor="transparent" stopOpacity="0"/>
                </radialGradient>
                <filter id="glow"><feGaussianBlur stdDeviation="3" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
              </defs>
              <circle cx={CX} cy={CY} r={R+80} fill="url(#bgGrad)"/>
              <circle cx={CX} cy={CY} r={R} fill="none" stroke="rgba(59,130,246,0.12)" strokeWidth="1" strokeDasharray="4 6"/>
              {clients.map((device,i)=>{
                const angle=(i/Math.max(clients.length,1))*2*Math.PI-Math.PI/2;
                const dx=CX+Math.cos(angle)*R,dy=CY+Math.sin(angle)*R;
                const isActive=device.status==='Active';
                const color=isActive?'rgba(59,130,246,0.35)':'rgba(100,116,139,0.2)';
                return (
                  <g key={`line-${device.id}`}>
                    <line x1={CX} y1={CY} x2={dx} y2={dy} stroke={color} strokeWidth={isActive?1.5:1} strokeDasharray={isActive?'none':'4 4'}/>
                    {isActive&&<circle r="3" fill="#3B82F6" opacity="0.7"><animateMotion dur={`${2+i*0.2}s`} repeatCount="indefinite" path={`M${CX},${CY} L${dx},${dy}`}/></circle>}
                  </g>
                );
              })}
              {clients.map((device,i)=>{
                const angle=(i/Math.max(clients.length,1))*2*Math.PI-Math.PI/2;
                const dx=CX+Math.cos(angle)*R,dy=CY+Math.sin(angle)*R;
                const color=typeColors[device.type]||'#6B7280';
                const isActive=device.status==='Active';
                const isSelected=topoSelected?.id===device.id;
                return (
                  <g key={device.id} style={{cursor:'pointer'}} onClick={()=>setTopoSelected(topoSelected?.id===device.id?null:device)}>
                    {isActive&&<circle cx={dx} cy={dy} r={isSelected?32:26} fill="none" stroke={color} strokeWidth="1" opacity="0.4"><animate attributeName="r" values={`${isSelected?32:26};${isSelected?38:32};${isSelected?32:26}`} dur="2s" repeatCount="indefinite"/><animate attributeName="opacity" values="0.4;0;0.4" dur="2s" repeatCount="indefinite"/></circle>}
                    <circle cx={dx} cy={dy} r={isSelected?26:22} fill={`${color}22`} stroke={isSelected?color:`${color}66`} strokeWidth={isSelected?2.5:1.5} filter={isSelected?'url(#glow)':'none'}/>
                    <circle cx={dx+16} cy={dy-16} r="5" fill={isActive?'#10B981':'#EF4444'} stroke="#0f172a" strokeWidth="1.5"/>
                    <text x={dx} y={dy+5} textAnchor="middle" fontSize="12" fill={color} fontWeight="600" style={{pointerEvents:'none'}}>{(device.type||'?').charAt(0)}</text>
                    <text x={dx} y={dy+40} textAnchor="middle" fontSize="9" fill="rgba(255,255,255,0.7)" style={{pointerEvents:'none'}}>{(device.name||'').substring(0,14)}</text>
                    <text x={dx} y={dy+52} textAnchor="middle" fontSize="9" fill="rgba(255,255,255,0.4)" style={{pointerEvents:'none'}}>{device.ip_address}</text>
                  </g>
                );
              })}
              <g style={{cursor:'pointer'}} onClick={()=>setTopoSelected(topoSelected?.id===router.id?null:router)}>
                <circle cx={CX} cy={CY} r={44} fill="rgba(59,130,246,0.08)" stroke="rgba(59,130,246,0.4)" strokeWidth="2"/>
                <circle cx={CX} cy={CY} r={36} fill="rgba(59,130,246,0.15)" stroke="rgba(59,130,246,0.6)" strokeWidth="2"/>
                <circle cx={CX+26} cy={CY-26} r="6" fill="#10B981" stroke="#0f172a" strokeWidth="2"/>
                <text x={CX} y={CY+5} textAnchor="middle" fontSize="11" fill="#60a5fa" fontWeight="700" style={{pointerEvents:'none'}}>GW</text>
                <text x={CX} y={CY+62} textAnchor="middle" fontSize="11" fill="rgba(255,255,255,0.8)" fontWeight="600" style={{pointerEvents:'none'}}>{router.name}</text>
                <text x={CX} y={CY+76} textAnchor="middle" fontSize="9" fill="rgba(255,255,255,0.4)" style={{pointerEvents:'none'}}>{router.ip_address}</text>
              </g>
            </svg>
            <div style={{width:'260px',borderLeft:'1px solid rgba(255,255,255,0.06)',overflowY:'auto',padding:'20px 16px',display:'flex',flexDirection:'column',gap:'8px'}}>
              {topoSelected?(
                <>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'8px'}}>
                    <span style={{fontWeight:600,fontSize:'0.95rem'}}>{topoSelected.name}</span>
                    <button style={{background:'none',border:'none',cursor:'pointer',opacity:0.5}} onClick={()=>setTopoSelected(null)}><X size={16}/></button>
                  </div>
                  {[['IP',topoSelected.ip_address],['MAC',topoSelected.mac_address],['Type',topoSelected.type],['Vendor',topoSelected.vendor],['Statut',topoSelected.status],['Signal',`${topoSelected.signal_strength||0}%`]].map(([k,v])=>(
                    <div key={k} style={{display:'flex',justifyContent:'space-between',fontSize:'0.8rem',padding:'6px 0',borderBottom:'1px solid rgba(255,255,255,0.04)'}}>
                      <span style={{opacity:0.5}}>{k}</span>
                      <span style={{fontFamily:'monospace',fontSize:'0.78rem',textAlign:'right',maxWidth:'140px',wordBreak:'break-all'}}>{v||'—'}</span>
                    </div>
                  ))}
                </>
              ):(
                <>
                  <div style={{fontSize:'0.8rem',opacity:0.5,marginBottom:'8px'}}>Appareils connectés</div>
                  {devices.map(d=>(
                    <div key={d.id} style={{display:'flex',alignItems:'center',gap:'10px',padding:'8px',borderRadius:'8px',cursor:'pointer',background:'rgba(255,255,255,0.03)',border:'1px solid rgba(255,255,255,0.05)'}} onClick={()=>setTopoSelected(d)}>
                      <div style={{width:'8px',height:'8px',borderRadius:'50%',background:d.status==='Active'?'#10B981':'#EF4444',flexShrink:0}}/>
                      <div style={{flex:1,minWidth:0}}>
                        <div style={{fontSize:'0.82rem',fontWeight:500,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{d.name}</div>
                        <div style={{fontSize:'0.72rem',opacity:0.45,color:getTypeColor(d.type)}}>{d.type} · {d.ip_address}</div>
                      </div>
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>
          <div style={{display:'flex',gap:'20px',padding:'14px 24px',borderTop:'1px solid rgba(255,255,255,0.06)',flexWrap:'wrap'}}>
            {[['#10B981','Actif'],['#EF4444','Hors ligne'],['#3B82F6','Routeur/Switch'],['#8B5CF6','PC/Laptop'],['#F59E0B','Serveur/NAS'],['#EF4444','Caméra']].map(([color,label])=>(
              <div key={label} style={{display:'flex',alignItems:'center',gap:'6px',fontSize:'0.78rem',opacity:0.7}}>
                <div style={{width:'10px',height:'10px',borderRadius:'50%',background:color}}/>
                {label}
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  const renderPerformance = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Performance</h1>
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Performance</span></div>
      </div>
      <div className="stats-grid" style={{gridTemplateColumns:'repeat(4,1fr)'}}>
        <StatCard title="Appareils actifs" value={devices.filter(d=>d.status==='Active').length} change="Connectés" icon={<Activity size={24}/>} color="#10B981"/>
        <StatCard title="Latence moy." value="8 ms" change="Réseau local" icon={<Wifi size={24}/>} color="#3B82F6"/>
        <StatCard title="Débit" value="142 Mbps" icon={<TrendingUp size={24}/>} color="#10B981" change="+LAN interne"/>
        <StatCard title="Disponibilité" value="99.8%" change="+0.1% ce mois" icon={<CheckCircle size={24}/>} color="#10B981"/>
      </div>
      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header"><h3 className="chart-title">Latence réseau (temps réel)</h3></div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={perfData}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode?'#334155':'#e2e8f0'}/>
              <XAxis dataKey="t" stroke={darkMode?'#94a3b8':'#64748b'}/>
              <YAxis stroke={darkMode?'#94a3b8':'#64748b'}/>
              <Tooltip contentStyle={{backgroundColor:darkMode?'#1e293b':'#ffffff',borderRadius:'8px'}}/>
              <Area type="monotone" dataKey="latency" stroke="#3B82F6" fill="#3B82F633" name="Latence (ms)"/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="chart-card fade-in">
          <div className="chart-header"><h3 className="chart-title">Débit réseau (Mbps)</h3></div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={perfData}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode?'#334155':'#e2e8f0'}/>
              <XAxis dataKey="t" stroke={darkMode?'#94a3b8':'#64748b'}/>
              <YAxis stroke={darkMode?'#94a3b8':'#64748b'}/>
              <Tooltip contentStyle={{backgroundColor:darkMode?'#1e293b':'#ffffff',borderRadius:'8px'}}/>
              <Area type="monotone" dataKey="throughput" stroke="#10B981" fill="#10B98133" name="Débit (Mbps)"/>
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
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Firewall</span></div>
      </div>
      <div className="stats-grid" style={{gridTemplateColumns:'repeat(3,1fr)'}}>
        <StatCard title="Règles actives" value="24" change="Configurées" icon={<ShieldCheck size={24}/>} color="#10B981"/>
        <StatCard title="Connexions bloquées" value="156" change="Aujourd'hui" icon={<Ban size={24}/>} color="#EF4444" positive={false}/>
        <StatCard title="Trafic autorisé" value="2.4 GB" change="Aujourd'hui" icon={<Wifi size={24}/>} color="#3B82F6"/>
      </div>
      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Règles du pare-feu</h3>
          <button className="btn btn-primary" onClick={()=>alert('Gestion des règles disponible')}><Plus size={14}/> Nouvelle règle</button>
        </div>
        <div className="table-container">
          <table className="data-table">
            <thead><tr><th>Nom</th><th>Type</th><th>Port</th><th>Protocole</th><th>Statut</th><th>Actions</th></tr></thead>
            <tbody>
              {[{name:'SSH Admin',type:'ALLOW',port:22,protocol:'TCP',status:'Active'},{name:'HTTP Web',type:'ALLOW',port:80,protocol:'TCP',status:'Active'},{name:'HTTPS Sécurisé',type:'ALLOW',port:443,protocol:'TCP',status:'Active'},{name:'Block P2P',type:'DENY',port:'6881-6889',protocol:'TCP/UDP',status:'Active'},{name:'DNS',type:'ALLOW',port:53,protocol:'UDP',status:'Active'},{name:'RDP Bloqué',type:'DENY',port:3389,protocol:'TCP',status:'Active'}].map((rule,i)=>(
                <tr key={i}>
                  <td>{rule.name}</td>
                  <td><span className={`badge ${rule.type==='ALLOW'?'badge-success':'badge-danger'}`}>{rule.type}</span></td>
                  <td className="font-mono">{rule.port}</td>
                  <td>{rule.protocol}</td>
                  <td><span className={`badge ${rule.status==='Active'?'badge-success':'badge-warning'}`}>{rule.status}</span></td>
                  <td><div className="table-actions">
                    <button className="btn btn-sm btn-secondary" onClick={()=>alert('Édition disponible')}><Edit size={14}/></button>
                    <button className="btn btn-sm btn-danger" onClick={()=>alert('Suppression disponible')}><Trash2 size={14}/></button>
                  </div></td>
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
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Logs</span></div>
      </div>
      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Journal d'activité</h3>
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={()=>handleExport('logs','csv')}><FileDown size={14}/> Export CSV</button>
            <button className="btn btn-secondary" onClick={()=>handleExport('logs','json')}><FileJson size={14}/> Export JSON</button>
          </div>
        </div>
        <div className="logs-container">
          {[...FAKE_ALERTS].reverse().map((alert,i)=>{
            const level=alert.severity==='critical'?'ERROR':alert.severity==='warning'?'WARN':'INFO';
            const ts=new Date(alert.timestamp);
            return (
              <div key={alert.id||i} className={`log-entry log-${level.toLowerCase()}`}>
                <span className="log-time">{ts.toLocaleTimeString('fr-FR')}</span>
                <span className={`log-level ${level.toLowerCase()}`}>{level}</span>
                <span className="log-action">{alert.alert_type}</span>
                <span className="log-user">system</span>
                <span className="log-ip font-mono">{alert.device_ip||'—'}</span>
                <span className={`log-status ${alert.resolved||resolvedAlerts.has(alert.id)?'success':''}`}>{alert.resolved||resolvedAlerts.has(alert.id)?'Résolu':'En attente'}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );

  const renderReports = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Rapports</h1>
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Reports</span></div>
      </div>
      <div className="chart-card fade-in">
        <div className="chart-header mb-20"><h3 className="chart-title">Générer un rapport</h3></div>
        <div className="report-options">
          <div className="report-type-selector">
            {[{id:'summary',name:'Résumé',icon:BarChart3,desc:"Vue d'ensemble"},{id:'devices',name:'Équipements',icon:Network,desc:'Liste détaillée'},{id:'security',name:'Sécurité',icon:Shield,desc:'Analyse des menaces'},{id:'performance',name:'Performance',icon:Activity,desc:'Métriques réseau'}].map(type=>(
              <div key={type.id} className="report-type-card"><type.icon size={32}/><h4>{type.name}</h4><p>{type.desc}</p></div>
            ))}
          </div>
          <div className="report-config">
            <div className="form-group"><label>Format</label><select className="form-control"><option>PDF</option><option>CSV</option><option>JSON</option></select></div>
            <div className="form-group"><label>Période</label><select className="form-control"><option>7 derniers jours</option><option>30 derniers jours</option></select></div>
          </div>
          <button className="btn btn-primary" onClick={handleGenerateReport}><FileText size={16}/> Générer le rapport</button>
        </div>
      </div>
      <div className="chart-card fade-in mt-20">
        <div className="chart-header mb-20"><h3 className="chart-title">Rapports récents</h3></div>
        <div className="table-container">
          <table className="data-table">
            <thead><tr><th>Nom</th><th>Type</th><th>Date</th><th>Format</th><th>Taille</th><th>Actions</th></tr></thead>
            <tbody>
              {[{name:'Rapport SUPNUM - Mars 2026',type:'Résumé',date:'16/03/2026',format:'PDF',size:'2.1 MB'},{name:'Audit sécurité Q1',type:'Sécurité',date:'01/03/2026',format:'PDF',size:'1.8 MB'},{name:'Export équipements',type:'Équipements',date:'01/03/2026',format:'CSV',size:'48 KB'}].map((report,i)=>(
                <tr key={i}>
                  <td>{report.name}</td><td>{report.type}</td><td>{report.date}</td>
                  <td><span className="badge badge-info">{report.format}</span></td><td>{report.size}</td>
                  <td><div className="table-actions">
                    <button className="btn btn-sm btn-secondary" onClick={handleGenerateReport}><EyeIcon size={14}/></button>
                    <button className="btn btn-sm btn-secondary" onClick={handleGenerateReport}><Download size={14}/></button>
                  </div></td>
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
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Statistics</span></div>
      </div>
      <div className="stats-grid">
        <StatCard title="Équipements ce mois" value={stats.total_devices} change={<><TrendingUp size={14}/> +12% vs mois dernier</>} icon={<Network size={24}/>}/>
        <StatCard title="Alertes traitées" value={alerts.length} change={<><TrendingDown size={14}/> -8% vs mois dernier</>} icon={<Bell size={24}/>} color="#10B981"/>
        <StatCard title="Nouveaux appareils" value={devices.filter(d=>d.is_new).length} change="Depuis dernier scan" icon={<Activity size={24}/>} color="#F59E0B"/>
        <StatCard title="Disponibilité" value="99.8%" change={<><TrendingUp size={14}/> +0.2%</>} icon={<CheckCircle size={24}/>} color="#10B981"/>
      </div>
      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header"><h3 className="chart-title">Évolution des équipements</h3></div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke={darkMode?'#334155':'#e2e8f0'}/>
              <XAxis dataKey="date" stroke={darkMode?'#94a3b8':'#64748b'}/>
              <YAxis stroke={darkMode?'#94a3b8':'#64748b'}/>
              <Tooltip contentStyle={{backgroundColor:darkMode?'#1e293b':'#ffffff',borderRadius:'8px'}}/>
              <Legend/>
              <Bar dataKey="active" fill="#10B981" name="Actifs"/>
              <Bar dataKey="offline" fill="#EF4444" name="Hors ligne"/>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="chart-card fade-in">
          <div className="chart-header"><h3 className="chart-title">Répartition par type</h3></div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie data={FAKE_PIE_DATA} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={110} label={({name,percent})=>`${name} ${(percent*100).toFixed(0)}%`}>
                {FAKE_PIE_DATA.map((entry,index)=><Cell key={index} fill={entry.color}/>)}
              </Pie>
              <Tooltip contentStyle={{backgroundColor:darkMode?'#1e293b':'#ffffff',borderRadius:'8px'}}/>
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
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Exports</span></div>
      </div>
      <div className="charts-grid">
        {[{title:'Équipements',desc:'Liste des appareils détectés',type:'devices',icon:Network},{title:'Alertes',desc:'Historique des alertes',type:'alerts',icon:Bell},{title:'Logs',desc:'Journal d\'activité',type:'logs',icon:History},{title:'Rapport PDF',desc:'Rapport complet du réseau',type:'report',icon:FileText}].map(item=>(
          <div key={item.type} className="chart-card fade-in">
            <div className="chart-header mb-20">
              <h3 className="chart-title"><item.icon size={18} style={{marginRight:'8px'}}/>{item.title}</h3>
            </div>
            <p style={{opacity:0.6,fontSize:'0.9rem',marginBottom:'16px'}}>{item.desc}</p>
            {item.type==='report'?(
              <div style={{display:'flex',gap:'8px'}}>
                <button className="btn btn-primary" onClick={handleGenerateReport}><FileText size={14}/> Générer PDF</button>
              </div>
            ):(
              <div style={{display:'flex',gap:'8px'}}>
                <button className="btn btn-secondary" onClick={()=>handleExport(item.type,'csv')}><FileSpreadsheet size={14}/> CSV</button>
                <button className="btn btn-secondary" onClick={()=>handleExport(item.type,'json')}><FileJson size={14}/> JSON</button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );

  const renderSettings = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Paramètres</h1>
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Settings</span></div>
      </div>
      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header mb-20"><h3 className="chart-title">Configuration réseau</h3></div>
          <div className="form-group" style={{marginBottom:'16px'}}>
            <label>Plage IP par défaut</label>
            <input type="text" className="form-control" value={settingsData.ip_range} onChange={e=>setSettingsData(s=>({...s,ip_range:e.target.value}))}/>
            <small style={{opacity:0.5,fontSize:'0.8rem'}}>Réseau SUPNUM : 10.17.11.0/24</small>
          </div>
          <div className="form-group" style={{marginBottom:'16px'}}>
            <label>Intervalle de scan automatique</label>
            <select className="form-control" value={settingsData.scan_interval} onChange={e=>setSettingsData(s=>({...s,scan_interval:e.target.value}))}>
              <option>Désactivé</option><option>5 minutes</option><option>15 minutes</option><option>30 minutes</option><option>1 heure</option>
            </select>
          </div>
          <div className="form-group">
            <label>Seuil de signal minimum (%)</label>
            <input type="number" className="form-control" value={settingsData.signal_threshold} onChange={e=>setSettingsData(s=>({...s,signal_threshold:parseInt(e.target.value)}))} min="0" max="100"/>
          </div>
        </div>
        <div className="chart-card fade-in">
          <div className="chart-header mb-20"><h3 className="chart-title">Notifications</h3></div>
          {[['Notifications par email','email_notif',true],['Alertes critiques','critical_notif',true],['Nouveaux appareils détectés','new_device_notif',true]].map(([label,key,def])=>(
            <div key={key} className="form-group" style={{marginBottom:'16px'}}>
              <label className="toggle-label">
                <span>{label}</span>
                <input type="checkbox" defaultChecked={def}/>
                <span className="toggle-slider"></span>
              </label>
            </div>
          ))}
        </div>
      </div>
      <div style={{display:'flex',gap:'12px',marginTop:'8px',justifyContent:'flex-end'}}>
        <button className="btn btn-secondary" onClick={()=>setSettingsData({ip_range:'10.17.11.0/24',scan_interval:'15 minutes',signal_threshold:30})}><RotateCcw size={14}/> Réinitialiser</button>
        <button className="btn btn-primary" onClick={handleSaveSettings}><Save size={14}/> Sauvegarder</button>
      </div>
    </div>
  );

  const renderUsers = () => (
    <div className="content">
      <div className="page-title mb-30">
        <h1>Utilisateurs</h1>
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">Users</span></div>
      </div>
      <div className="chart-card fade-in">
        <div className="chart-header mb-20">
          <h3 className="chart-title">Gestion des utilisateurs</h3>
          <button className="btn btn-primary" onClick={()=>setEditingUser({id:null,username:'',email:'',full_name:'',role:'user',is_active:true,password:''})}><Plus size={14}/> Nouvel utilisateur</button>
        </div>
        <div className="table-container">
          <table className="data-table">
            <thead><tr><th>Utilisateur</th><th>Email</th><th>Nom complet</th><th>Rôle</th><th>Statut</th><th>Actions</th></tr></thead>
            <tbody>
              {users.map(user=>(
                <tr key={user.id}>
                  <td>
                    <div style={{display:'flex',alignItems:'center',gap:'10px'}}>
                      <div style={{width:'32px',height:'32px',borderRadius:'50%',background:'rgba(59,130,246,0.2)',display:'flex',alignItems:'center',justifyContent:'center',fontWeight:600,fontSize:'0.9rem',color:'#60a5fa'}}>
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                      <span style={{fontWeight:500}}>{user.username}</span>
                    </div>
                  </td>
                  <td style={{opacity:0.7,fontSize:'0.85rem'}}>{user.email||'—'}</td>
                  <td style={{opacity:0.8}}>{user.full_name}</td>
                  <td><span className={`badge ${user.role==='admin'?'badge-warning':'badge-info'}`}>{user.role==='admin'?'Admin':'Utilisateur'}</span></td>
                  <td><span className={`badge ${user.is_active?'badge-success':'badge-danger'}`}>{user.is_active?'Actif':'Inactif'}</span></td>
                  <td>
                    <div className="table-actions">
                      <button className="btn btn-sm btn-secondary" onClick={()=>setEditingUser({...user})}><Edit size={14}/></button>
                      {user.username!=='admin'&&<button className="btn btn-sm btn-danger" onClick={()=>setUsers(prev=>prev.filter(u=>u.id!==user.id))}><Trash2 size={14}/></button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {editingUser&&(
        <div className="modal-overlay" onClick={()=>setEditingUser(null)}>
          <div className="modal" onClick={e=>e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingUser.id?'Modifier':'Nouvel utilisateur'}</h3>
              <button className="modal-close" onClick={()=>setEditingUser(null)}><X size={20}/></button>
            </div>
            <div className="modal-body">
              {[['Nom complet','full_name','text'],['Nom d\'utilisateur','username','text'],['Email','email','email'],['Mot de passe','password','password']].map(([label,key,type])=>(
                <div key={key} className="form-group" style={{marginBottom:'12px'}}>
                  <label>{label}</label>
                  <input type={type} className="form-control" value={editingUser[key]||''} onChange={e=>setEditingUser({...editingUser,[key]:e.target.value})}/>
                </div>
              ))}
              <div className="form-group" style={{marginBottom:'12px'}}>
                <label>Rôle</label>
                <select className="form-control" value={editingUser.role} onChange={e=>setEditingUser({...editingUser,role:e.target.value})}>
                  <option value="user">Utilisateur</option><option value="admin">Administrateur</option>
                </select>
              </div>
              <div className="form-group">
                <label className="toggle-label">
                  <span>Compte actif</span>
                  <input type="checkbox" checked={editingUser.is_active!==false} onChange={e=>setEditingUser({...editingUser,is_active:e.target.checked})}/>
                  <span className="toggle-slider"></span>
                </label>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={()=>setEditingUser(null)}>Annuler</button>
              <button className="btn btn-primary" onClick={handleSaveUser}><Save size={14}/> Sauvegarder</button>
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
        <div className="page-breadcrumb"><span>NetMon+</span><ChevronRight size={12}/><span className="font-semibold">System</span></div>
      </div>
      <div className="stats-grid" style={{gridTemplateColumns:'repeat(4,1fr)'}}>
        <StatCard title="Appareils total" value={stats.total_devices} change="En base" icon={<Network size={24}/>} color="#3B82F6"/>
        <StatCard title="Actifs" value={stats.active_devices} change="Connectés" icon={<WifiHigh size={24}/>} color="#10B981"/>
        <StatCard title="Alertes ouvertes" value={alerts.filter(a=>!a.resolved&&!resolvedAlerts.has(a.id)).length} change="À traiter" icon={<Bell size={24}/>} color="#F59E0B"/>
        <StatCard title="Dernier scan" value={lastScan?lastScan.toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}):'—'} change="Heure" icon={<Clock size={24}/>} color="#8B5CF6"/>
      </div>
      <div className="charts-grid">
        <div className="chart-card fade-in">
          <div className="chart-header mb-20"><h3 className="chart-title">Informations système</h3></div>
          <div className="system-info">
            {[['Version','NetMon+ v1.0.0'],['Institut','SUPNUM — Mauritanie'],['Base de données','SQLite (netmon.db)'],['API','FastAPI v0.100.0'],['Python','3.11.4'],['Scheduler','APScheduler actif'],['Réseau scanné',ipRange],['Mode','Démo (données simulées)']].map(([k,v])=>(
              <div key={k} className="info-row"><span className="info-label">{k}</span><span className="info-value">{v}</span></div>
            ))}
          </div>
        </div>
        <div className="chart-card fade-in">
          <div className="chart-header mb-20"><h3 className="chart-title">Maintenance</h3></div>
          <div className="maintenance-actions">
            <button className="btn btn-secondary" onClick={()=>downloadBlob(new Blob(['{}'],{type:'application/octet-stream'}),'netmon_backup.db')}><Download size={14}/> Sauvegarder la base</button>
            <button className="btn btn-secondary" onClick={()=>alert('Aucune mise à jour disponible.')}><RefreshCw size={14}/> Vérifier mises à jour</button>
            <button className="btn btn-danger" onClick={()=>alert('Redémarrage demandé (démo).')}><RotateCcw size={14}/> Redémarrer le service</button>
          </div>
          <div className="system-logs-link">
            <button className="btn btn-link" onClick={()=>setActivePage('logs')}><History size={14}/> Voir les logs système</button>
          </div>
        </div>
      </div>
    </div>
  );

  const renderPage = () => {
    switch(activePage) {
      case 'dashboard':   return renderDashboard();
      case 'scan':        return renderScan();
      case 'devices':     return renderDevices();
      case 'alerts':      return renderAlerts();
      case 'topology':    return renderTopology();
      case 'performance': return renderPerformance();
      case 'firewall':    return renderFirewall();
      case 'logs':        return renderLogs();
      case 'reports':     return renderReports();
      case 'statistics':  return renderStatistics();
      case 'exports':     return renderExports();
      case 'settings':    return renderSettings();
      case 'users':       return renderUsers();
      case 'system':      return renderSystem();
      default:            return renderDashboard();
    }
  };

  if(!isLoggedIn) return renderAuthPage();

  return (
    <div className={`app-container ${darkMode?'':'light'}`}>
      <aside className={`sidebar ${sidebarOpen?'open':''}`}>
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="logo-icon"><Wifi size={24} color="white"/></div>
            <div>
              <div className="logo-text">NetMon+</div>
              <div className="sidebar-subtitle">Network Monitor Pro</div>
            </div>
          </div>
        </div>
        <div className="user-profile">
          <div className="user-avatar">{currentUser?.username?.charAt(0).toUpperCase()||'A'}</div>
          <div className="user-info">
            <div className="user-name">{currentUser?.username}</div>
            <div className="user-role">{currentUser?.role==='admin'?'Administrateur':'Utilisateur'}</div>
          </div>
        </div>
        <nav className="sidebar-menu">
          {menuSections.map((section,index)=>(
            <div key={index} className="menu-section">
              <div className="menu-title">{section.title}</div>
              <ul className="menu-items">
                {section.items.map(item=>{
                  const Icon=item.icon;
                  return (
                    <li key={item.id} className="menu-item">
                      <button onClick={()=>{setActivePage(item.id);if(window.innerWidth<992)setSidebarOpen(false);}} className={`menu-link ${activePage===item.id?'active':''}`}>
                        <Icon className="menu-icon" size={18}/>
                        <span>{item.label}</span>
                        {item.badge>0&&<span className="menu-badge">{item.badge}</span>}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button className="logout-btn" onClick={handleLogout}><LogOut size={16}/> Déconnexion</button>
        </div>
      </aside>
      <main className="main-content">
        <header className="header">
          <button className="mobile-menu-btn" onClick={()=>setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen?<X size={24}/>:<Menu size={24}/>}
          </button>
          <div style={{flex:1}}/>
          <div className="header-actions">
            <button className="theme-toggle" onClick={()=>setDarkMode(!darkMode)}>
              {darkMode?<Sun size={20}/>:<Moon size={20}/>}
            </button>
          </div>
        </header>
        <AnimatePresence mode="wait">
          <motion.div key={activePage} initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} transition={{duration:0.15}}>
            {renderPage()}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
};

export default App;