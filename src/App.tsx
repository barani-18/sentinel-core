import { useEffect, useState, useMemo } from "react"
import {
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  CartesianGrid,
  Legend
} from "recharts"
import { supabase } from './supabaseClient';

// ---------- Types ----------
type Severity = "low" | "medium" | "high"
type AlertStatus = "open" | "investigating" | "blocked" | "isolated" | "ignored" | "escalated" | "resolved"

interface Alert {
  id: string; ts: number; type: string; severity: Severity;
  confidence: number; srcIp: string; host: string; status: AlertStatus;
}
interface LogEntry { id: string; ts: number; msg: string; kind: string; }
interface User { username: string; role: string; name: string; avatar: string }
interface HostInfo { id: string; risk: number; cpu: number; compromised: boolean; }
interface HistoryPoint { step: number; anomaly: number; cpu: number; threats: number; compromised: number; }

const fmtTime = (ts: number) => new Date(ts).toLocaleTimeString()

// ---------- Main Entry ----------
export default function App() {
  const [session, setSession] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session)
      setLoading(false)
    })
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session)
    })
    return () => subscription.unsubscribe()
  }, [])

  if (loading) return <div className="min-h-screen bg-[#030508] flex items-center justify-center text-cyan-500 font-mono text-sm tracking-widest animate-pulse">INITIALIZING SOC...</div>

  if (!session) return <LoginPortal onLogin={async (u, p) => {
    const { error } = await supabase.auth.signInWithPassword({ email: u, password: p });
    return !error;
  }} />

  const currentUser: User = {
    username: session.user.email || "Operator",
    name: session.user.user_metadata?.full_name || "Security Analyst",
    role: session.user.user_metadata?.role || "analyst",
    avatar: session.user.user_metadata?.avatar || "OP",
  }

  return <SOCDashboard user={currentUser} onLogout={() => supabase.auth.signOut()} />
}

// ---------- Login Portal ----------
function LoginPortal({ onLogin }: any) {
  const [u, setU] = useState(""); const [p, setP] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleLogin = async () => {
      setIsSubmitting(true);
      const success = await onLogin(u,p);
      if (!success) { alert("Invalid credentials"); setIsSubmitting(false); }
  }

  return (
    <div className="min-h-screen bg-[#030508] text-white flex items-center justify-center font-sans relative overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(6,182,212,0.1),_transparent_50%)]" />
      <div className="w-full max-w-sm bg-zinc-950/80 border border-white/10 p-10 rounded-[32px] backdrop-blur-xl shadow-2xl relative z-10">
        <div className="text-center mb-8">
          <div className="w-12 h-12 bg-cyan-500 rounded-2xl mx-auto mb-4 flex items-center justify-center shadow-[0_0_30px_rgba(6,182,212,0.3)]"><ShieldIcon /></div>
          <h2 className="text-2xl font-bold tracking-tight">Secure Access</h2>
          <p className="text-xs text-zinc-500 mt-2">Production SOC Environment</p>
        </div>
        <div className="space-y-4">
          <input className="w-full p-4 bg-zinc-900 border border-white/5 rounded-2xl outline-none focus:ring-1 focus:ring-cyan-500 transition-all text-sm" placeholder="Operator Email" value={u} onChange={e=>setU(e.target.value)} />
          <input className="w-full p-4 bg-zinc-900 border border-white/5 rounded-2xl outline-none focus:ring-1 focus:ring-cyan-500 transition-all text-sm" type="password" placeholder="Passphrase" value={p} onChange={e=>setP(e.target.value)} />
          <button disabled={isSubmitting} className="w-full p-4 bg-white text-black font-black rounded-2xl hover:bg-zinc-200 transition-all disabled:opacity-50" onClick={handleLogin}>
              {isSubmitting ? "Verifying..." : "Initialize Session"}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------- SOC Dashboard ----------
function SOCDashboard({ user, onLogout }: { user: User; onLogout: () => void }) {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [selectedAlert, setSelectedAlert] = useState("")
  const [currentPage, setCurrentPage] = useState<1 | 2>(2) // Defaulting to Analytics for you!
  
  // Settings
  const [autoPlay, setAutoPlay] = useState(false)
  const [speed, setSpeed] = useState(1500)

  // Simulation State for Live Charts
  const [tick, setTick] = useState(0);
  const [hosts, setHosts] = useState<HostInfo[]>(Array.from({length: 12}).map((_, i) => ({ id: `h-${String(i+1).padStart(2,'0')}`, risk: Math.random()*0.2, cpu: Math.random()*0.3, compromised: false })));
  const [history, setHistory] = useState<HistoryPoint[]>(Array.from({length: 20}).map((_, i) => ({ step: i, anomaly: 0.2, cpu: 0.2, threats: 0, compromised: 0 })));

  // ⚡️ REAL-TIME FETCH ⚡️
  const fetchData = async () => {
    const { data: aData } = await supabase.from('alerts').select('*').order('created_at', { ascending: false });
    const { data: lData } = await supabase.from('logs').select('*').order('created_at', { ascending: false }).limit(30);
    if (aData) setAlerts(aData.map(d => ({ ...d, id: d.id.toString(), ts: new Date(d.created_at).getTime(), srcIp: d.srcip || d.srcIp })));
    if (lData) setLogs(lData.map(d => ({ ...d, id: d.id.toString(), ts: new Date(d.created_at).getTime() })));
  };

  useEffect(() => {
    fetchData();
    const channel = supabase.channel('soc-realtime')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'alerts' }, () => fetchData())
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'logs' }, () => fetchData())
      .subscribe();
    return () => { supabase.removeChannel(channel) };
  }, []);

  // 📈 LIVE METRICS TICKER (Drives the charts) 📈
  useEffect(() => {
    const interval = setInterval(() => {
        setTick(t => t + 1);
        
        const openAlerts = alerts.filter(a => a.status === 'open');
        const activeThreatsCount = openAlerts.length;
        
        let newCompromisedCount = 0;

        setHosts(prev => prev.map(h => {
            const targeted = openAlerts.filter(a => a.host === h.id);
            const risk = Math.min(1, h.risk * 0.95 + (targeted.length * 0.15) + (Math.random() * 0.05));
            const cpu = Math.min(1, 0.2 + (targeted.length * 0.2) + (Math.random() * 0.15));
            const compromised = targeted.some(a => a.severity === 'high') || risk > 0.85;
            if (compromised) newCompromisedCount++;
            return { ...h, risk, cpu, compromised };
        }));

        setHistory(prev => {
            const next = [...prev.slice(1)];
            const avgCpu = hosts.reduce((sum, h) => sum + h.cpu, 0) / 12;
            const anomaly = Math.min(1, 0.2 + (activeThreatsCount * 0.08) + (newCompromisedCount * 0.1) + (Math.random() * 0.05));
            next.push({ step: tick, anomaly, cpu: avgCpu, threats: activeThreatsCount, compromised: newCompromisedCount });
            return next;
        });

    }, 1000);
    return () => clearInterval(interval);
  }, [alerts, hosts, tick]);

  // 🕹 ACTIONS & AI 🕹
  const doAction = async (status: AlertStatus, label: string, targetId: string = selectedAlert, actor: string = user.name) => {
    if (!targetId) return;
    await supabase.from('alerts').update({ status }).eq('id', targetId);
    await supabase.from('logs').insert([{ msg: `${label} performed by ${actor} on A-${targetId.toString().slice(-4)}`, kind: status === 'resolved' ? 'success' : 'info' }]);
  };

  const runAgentStep = async () => {
    const { data } = await supabase.from('alerts').select('*').eq('status', 'open').order('created_at', { ascending: true }).limit(1);
    if (data && data.length > 0) {
        const target = data[0];
        let action: AlertStatus = 'investigating'; let label = 'Investigation';
        if (target.type.includes('Ransomware') || target.type.includes('C2 Traffic')) { action = 'isolated'; label = 'Auto-Isolation (Critical)'; }
        else if (target.type.includes('BruteForce') || target.type.includes('Scan')) { action = 'blocked'; label = 'Auto-Block IP'; }
        else if (target.severity === 'high') { action = 'escalated'; label = 'Auto-Escalation'; }
        else { action = 'resolved'; label = 'Auto-Resolution'; }
        await doAction(action, `🤖 Agent: ${label}`, target.id.toString(), 'Sentinel-AI');
    }
  }

  const generateAttack = async () => {
    const TYPES = ['Suspicious PowerShell Execution', 'RDP BruteForce Attempt', 'Ransomware.WannaCry', 'SQL Injection Payload', 'PortScan'];
    const type = TYPES[Math.floor(Math.random() * TYPES.length)];
    const ip = `203.${Math.floor(Math.random()*255)}.10.${Math.floor(Math.random()*255)}`;
    const hostId = `h-${String(Math.floor(Math.random()*12)+1).padStart(2,'0')}`;
    const conf = +(Math.random() * (0.99 - 0.6) + 0.6).toFixed(2);
    const sev: Severity = conf > 0.85 ? 'high' : conf > 0.7 ? 'medium' : 'low';
    await supabase.from('alerts').insert([{ type, severity: sev, confidence: conf, srcip: ip, host: hostId, status: 'open' }]);
  }

  useEffect(() => {
    if (!autoPlay) return;
    const interval = setInterval(() => {
      if (Math.random() > 0.7) { generateAttack(); } else { runAgentStep(); }
    }, speed);
    return () => clearInterval(interval);
  }, [autoPlay, speed]);

  const resetEnvironment = async () => {
    await supabase.from('alerts').delete().neq('id', '0');
    await supabase.from('logs').insert([{ msg: "Environment Reset initiated by Operator", kind: "warn" }]);
    setHosts(Array.from({length: 12}).map((_, i) => ({ id: `h-${String(i+1).padStart(2,'0')}`, risk: Math.random()*0.1, cpu: Math.random()*0.2, compromised: false })));
  };

  const currentMetrics = history[history.length - 1];
  const score = Math.max(0, 100 - (currentMetrics.threats * 5) - (currentMetrics.compromised * 15));
  const threatGauge = Math.min(100, (currentMetrics.threats * 15) + (currentMetrics.compromised * 25));

  return (
    <div className="min-h-screen bg-[#070a0f] text-zinc-100 flex font-inter">
      {/* Sidebar */}
      <aside className="w-64 border-r border-white/10 bg-[#040812] p-6 flex flex-col shrink-0 relative z-10 shadow-2xl">
        <div className="absolute top-0 left-0 w-full h-32 bg-cyan-500/10 blur-3xl opacity-30 pointer-events-none" />
        <div className="mb-10 text-white font-bold text-lg tracking-tight flex items-center gap-2">
            <div className="p-1.5 bg-cyan-500 rounded-md shadow-lg shadow-cyan-500/20 text-black"><ShieldIcon /></div>
            Sentinel-Core
        </div>
        <nav className="flex-1 space-y-2">
          <button onClick={()=>setCurrentPage(1)} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition ${currentPage===1 ? 'bg-cyan-500/10 text-cyan-400 ring-1 ring-cyan-500/20 font-bold' : 'text-zinc-500 hover:bg-white/5'}`}><GridIcon /> Operation</button>
          <button onClick={()=>setCurrentPage(2)} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition ${currentPage===2 ? 'bg-cyan-500/10 text-cyan-400 ring-1 ring-cyan-500/20 font-bold' : 'text-zinc-500 hover:bg-white/5'}`}><ChartIcon /> Analytics</button>
        </nav>
        <div className="pt-6 border-t border-white/5 flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-blue-600 flex items-center justify-center font-bold text-xs">{user.avatar}</div>
          <div className="min-w-0"><div className="text-sm font-bold truncate">{user.name}</div><button onClick={onLogout} className="text-[10px] text-zinc-500 hover:text-white uppercase tracking-widest mt-1">Sign out</button></div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col bg-[#0b0e14] overflow-y-auto">
        <header className="p-4 border-b border-white/5 bg-black/40 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-20 backdrop-blur-xl shadow-sm">
          <div className="flex items-center gap-4">
            <div><h1 className="text-sm font-bold">{currentPage === 1 ? "Operations Center" : "Analytics Center"}</h1><p className="text-[10px] text-zinc-500 uppercase tracking-widest">Autonomous Cloud-Native SOC Analyst</p></div>
            <div className="px-3 py-1 bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/20 rounded-full text-xs font-bold shadow-[0_0_15px_rgba(16,185,129,0.1)]">Score: {score}%</div>
            <div className="px-3 py-1 bg-transparent border border-white/10 text-zinc-300 rounded-full text-[10px] hidden lg:block">Selected Alert: <span className="font-mono text-white">{selectedAlert ? `A-${selectedAlert.slice(-4)}` : 'NONE'}</span></div>
          </div>
          
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={resetEnvironment} className="px-4 py-1.5 bg-transparent border border-white/10 text-zinc-300 rounded-full text-[10px] font-bold hover:bg-white/5">Reset Environment</button>
            <button onClick={generateAttack} className="px-4 py-1.5 bg-transparent border border-white/10 text-zinc-300 rounded-full text-[10px] font-bold hover:bg-white/5 hidden md:block">Inject Threat</button>
            <button onClick={runAgentStep} className="px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-full text-[10px] font-bold hover:bg-cyan-500/20">Run Step</button>
            
            <div className="flex items-center gap-3 bg-transparent border border-white/10 rounded-full px-4 py-1.5 ml-2">
                <span className="text-[10px] font-bold text-zinc-300">Auto-play: <span className={autoPlay ? 'text-cyan-400' : 'text-zinc-500'}>{autoPlay ? 'On' : 'Off'}</span></span>
                <input type="range" min="500" max="3000" value={speed} onChange={e=>setSpeed(Number(e.target.value))} className="w-16 h-1 accent-cyan-500 cursor-pointer hidden sm:block" />
                <div className={`w-7 h-4 rounded-full p-0.5 cursor-pointer transition-colors ${autoPlay ? 'bg-cyan-500' : 'bg-zinc-700'}`} onClick={() => setAutoPlay(!autoPlay)}>
                    <div className={`w-3 h-3 bg-white rounded-full transition-transform ${autoPlay ? 'translate-x-3' : 'translate-x-0'}`} />
                </div>
            </div>
          </div>
        </header>

        <div className="p-6">
          {currentPage === 1 ? (
            <div className="grid grid-cols-12 gap-6">
              <div className="col-span-12 xl:col-span-8 space-y-6">
                <Card title="Alerts Panel" subtitle="Real-time detections across VPC, EDR, WAF, CloudTrail" icon={<AlertIcon />}>
                  <div className="max-h-[450px] overflow-y-auto rounded-xl border border-white/5 bg-[#121214] shadow-inner">
                    <table className="w-full text-left text-[11px]">
                      <thead className="bg-[#121214] text-zinc-500 uppercase tracking-[0.15em] text-[9px] sticky top-0 shadow-sm">
                        <tr><th className="p-4">ID</th><th>Time</th><th>Type</th><th>Severity</th><th>Conf</th><th>Src IP</th><th>Host</th><th>Status</th></tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {alerts.map(a => (
                          <tr key={a.id} onClick={()=>setSelectedAlert(a.id)} className={`hover:bg-white/[0.03] cursor-pointer transition-colors ${selectedAlert === a.id ? 'bg-cyan-500/10' : ''}`}>
                            <td className="p-4 font-mono text-zinc-500 text-[10px]">A-{a.id.slice(-4)}</td>
                            <td className="text-zinc-500 font-mono text-[10px]">{fmtTime(a.ts)}</td>
                            <td className={`font-bold ${a.status === 'open' ? 'text-zinc-200' : 'text-zinc-600'}`}>{a.type}</td>
                            <td><SeverityPill sev={a.severity} dimmed={a.status !== 'open'} /></td>
                            <td className="text-zinc-400 font-mono">{Math.round(a.confidence*100)}%</td>
                            <td className="font-mono text-zinc-500">{a.srcIp}</td>
                            <td className="font-mono text-zinc-500">{a.host}</td>
                            <td><StatusPill status={a.status}/></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>

                <Card title="Action Controls" subtitle="Respond to selected alert" icon={<BoltIcon />}>
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                        <div className="text-[10px] text-zinc-500 uppercase tracking-widest hidden sm:block">Selected</div>
                        <div className="text-white font-mono bg-zinc-900 border border-white/5 px-3 py-1.5 rounded-lg text-xs">{selectedAlert ? `A-${selectedAlert.slice(-4)}` : '----'}</div>
                    </div>
                    <div className="flex gap-2 flex-wrap">
                        <ActionButton icon={<SearchIcon />} label="Investigate" onClick={()=>doAction('investigating', 'Manual Investigation')} />
                        <ActionButton icon={<BanIcon />} label="Block IP" onClick={()=>doAction('blocked', 'Manual IP Block')} />
                        <ActionButton icon={<IsolateIcon />} label="Isolate Host" onClick={()=>doAction('isolated', 'Manual Host Isolation')} />
                        <ActionButton icon={<IgnoreIcon />} label="Ignore" color="red" onClick={()=>doAction('ignored', 'Manual Ignore')} />
                        <ActionButton icon={<EscalateIcon />} label="Escalate" onClick={()=>doAction('escalated', 'Manual Escalation')} />
                        <ActionButton icon={<CheckIcon />} label="Resolve" color="green" onClick={()=>doAction('resolved', 'Manual Resolution')} />
                    </div>
                  </div>
                  <div className="mt-4 text-[9px] text-zinc-600">Tip: Use keyboard shortcuts — B Block | I Investigate | S Isolate</div>
                </Card>
              </div>

              <div className="col-span-12 xl:col-span-4 space-y-6">
                <Card title="Activity Logs" subtitle="Actions, rewards, and system changes" icon={<LogsIcon />}>
                  <div className="h-[350px] overflow-y-auto space-y-3 pr-2">
                    {logs.map(l => {
                      const isAI = l.msg.includes('Auto-Agent') || l.msg.includes('Agent');
                      const isError = l.kind === 'error';
                      return (
                        <div key={l.id} className={`flex gap-3 p-3 rounded-xl border ${isError ? 'bg-red-500/5 border-red-500/10' : isAI ? 'bg-cyan-500/5 border-cyan-500/10' : 'bg-[#18181b] border-white/5'}`}>
                          <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${isError ? 'bg-red-500 shadow-[0_0_8px_red]' : isAI ? 'bg-cyan-400' : l.kind==='success' ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                          <div>
                            <div className={`text-[11px] leading-relaxed ${isError ? 'text-red-300 font-bold' : isAI ? 'text-cyan-300' : 'text-zinc-300'}`}>{l.msg}</div>
                            <div className="text-[9px] text-zinc-500 uppercase mt-1 tracking-wider font-mono">{fmtTime(l.ts)}</div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </Card>

                <Card title="Quick Status" subtitle="Current system state" icon={<GridIcon />}>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-[#18181b] border border-white/5 rounded-xl p-4">
                      <div className="text-[9px] text-zinc-500 uppercase tracking-widest mb-1">Compromised</div>
                      <div className="text-3xl font-bold text-red-500">{currentMetrics.compromised}</div>
                      <div className="text-[9px] text-zinc-600 mt-1">of 12 hosts</div>
                    </div>
                    <div className="bg-[#18181b] border border-white/5 rounded-xl p-4">
                      <div className="text-[9px] text-zinc-500 uppercase tracking-widest mb-1">Threat Level</div>
                      <div className="text-3xl font-bold text-amber-500">{Math.round(threatGauge)}%</div>
                      <div className="text-[9px] text-zinc-600 mt-1">{threatGauge > 70 ? 'Critical' : threatGauge > 30 ? 'Elevated' : 'Normal'}</div>
                    </div>
                  </div>
                </Card>
              </div>
            </div>
          ) : (
            // ==========================================
            // FULL ANALYTICS PAGE (Matching Screenshots)
            // ==========================================
            <div className="space-y-4 max-w-[1600px] mx-auto pb-10">
              
              {/* SECTION 1: SYSTEM METRICS */}
              <Card title="System Metrics" subtitle="Live cloud SOC health monitoring" icon={<ChartIcon />}>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                  <MetricCard label="Compromised Hosts" value={currentMetrics.compromised} sub="12 total" color="text-red-400" border="border-red-500/20" />
                  <MetricCard label="Anomaly Score" value={`${Math.round(currentMetrics.anomaly * 100)}%`} sub="higher is worse" color="text-amber-500" border="border-amber-500/20" />
                  <MetricCard label="CPU Usage" value={`${Math.round(currentMetrics.cpu * 100)}%`} sub="cluster average" color="text-cyan-400" border="border-cyan-500/20" />
                  <MetricCard label="Active Threats" value={currentMetrics.threats} sub="current count" color="text-violet-400" border="border-violet-500/20" />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Threat Gauge */}
                    <div className="bg-[#121214] border border-white/5 rounded-xl p-4">
                        <div className="text-[10px] text-zinc-400 mb-3">Threat Level Gauge</div>
                        <div className="w-full h-3 bg-zinc-800 rounded-full overflow-hidden flex">
                            <div className="h-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500 transition-all duration-500" style={{ width: `${threatGauge}%` }} />
                        </div>
                        <div className="flex justify-between mt-2 text-[10px]">
                            <span className="text-zinc-500">0%</span>
                            <span className="text-amber-500 font-bold">{Math.round(threatGauge)}%</span>
                            <span className="text-zinc-500">100%</span>
                        </div>
                    </div>

                    {/* Sparkline 1 */}
                    <div className="bg-[#121214] border border-white/5 rounded-xl p-4">
                        <div className="text-[10px] text-zinc-400 mb-2">Anomaly Score Trend</div>
                        <div className="h-10 w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={history.slice(-10)}>
                                    <Area type="monotone" dataKey="anomaly" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.2} strokeWidth={2} isAnimationActive={false} />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Sparkline 2 */}
                    <div className="bg-[#121214] border border-white/5 rounded-xl p-4">
                        <div className="text-[10px] text-zinc-400 mb-2">Host Risk Distribution</div>
                        <div className="h-10 w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={hosts}>
                                    <Bar dataKey="risk" fill="#22d3ee" radius={[2,2,0,0]} isAnimationActive={false} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                </div>
              </Card>

              {/* SECTION 2: TIMELINE */}
              <Card title="System Health Timeline" subtitle="Comprehensive view: Anomaly, CPU, Threats, Compromised hosts over time">
                <div className="h-[250px] w-full mt-4">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={history}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                            <XAxis dataKey="step" hide />
                            <YAxis yAxisId="left" domain={[0, 1]} stroke="#52525b" fontSize={10} tickFormatter={(val)=>val.toFixed(2)} />
                            <YAxis yAxisId="right" orientation="right" domain={[0, 12]} stroke="#52525b" fontSize={10} />
                            <Tooltip contentStyle={{backgroundColor: '#09090b', border: '1px solid #ffffff10', borderRadius: '8px'}} itemStyle={{fontSize: '11px'}} labelStyle={{display: 'none'}} />
                            <Legend wrapperStyle={{fontSize: '11px', color: '#a1a1aa'}} iconType="circle" />
                            <Line yAxisId="left" type="monotone" dataKey="anomaly" name="Anomaly Score" stroke="#f59e0b" strokeWidth={2} dot={false} isAnimationActive={false} />
                            <Line yAxisId="left" type="monotone" dataKey="cpu" name="CPU Usage" stroke="#22d3ee" strokeWidth={2} dot={false} isAnimationActive={false} />
                            <Line yAxisId="right" type="monotone" dataKey="threats" name="Active Threats" stroke="#a78bfa" strokeWidth={2} dot={false} isAnimationActive={false} />
                            <Line yAxisId="right" type="stepAfter" dataKey="compromised" name="Compromised Hosts" stroke="#f43f5e" strokeWidth={2} dot={false} isAnimationActive={false} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
              </Card>

              {/* SECTION 3: CPU & ANOMALY */}
              <Card title="CPU & Anomaly Trend" subtitle="Detailed performance metrics over time" icon={<LogsIcon />}>
                <div className="h-[200px] w-full mt-4">
                    <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={history}>
                            <defs>
                                <linearGradient id="colorAnomLg" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4}/><stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/></linearGradient>
                                <linearGradient id="colorCpuLg" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#22d3ee" stopOpacity={0.4}/><stop offset="95%" stopColor="#22d3ee" stopOpacity={0}/></linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                            <XAxis dataKey="step" hide />
                            <YAxis domain={[0, 1]} stroke="#52525b" fontSize={10} tickFormatter={(val)=>val.toFixed(2)} />
                            <Tooltip contentStyle={{backgroundColor: '#121214', border: '1px solid #ffffff20', borderRadius: '8px'}} itemStyle={{fontSize: '12px'}} labelStyle={{display: 'none'}} />
                            <Legend wrapperStyle={{fontSize: '11px'}} iconType="circle" />
                            <Area type="monotone" dataKey="anomaly" name="Anomaly Score" stroke="#f59e0b" fill="url(#colorAnomLg)" strokeWidth={2} isAnimationActive={false} />
                            <Area type="monotone" dataKey="cpu" name="CPU Usage" stroke="#22d3ee" fill="url(#colorCpuLg)" strokeWidth={2} isAnimationActive={false} />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>
              </Card>

              {/* SECTION 4: HOST HEATMAP */}
              <Card title="Host Risk Heatmap" subtitle="Per-host risk levels across infrastructure" icon={<GridIcon />}>
                <div className="grid grid-cols-4 md:grid-cols-6 lg:grid-cols-12 gap-2 mt-4">
                    {hosts.map(h => {
                        const isRed = h.risk > 0.8 || h.compromised;
                        const isAmber = h.risk > 0.4 && !isRed;
                        const colors = isRed ? 'bg-red-500/10 border-red-500/30 text-red-400' : isAmber ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
                        return (
                            <div key={h.id} className={`border rounded-lg p-3 ${colors} flex flex-col items-center justify-center transition-colors`}>
                                <div className="text-[10px] font-mono text-zinc-300">{h.id}</div>
                                <div className="text-lg font-bold my-1">{Math.round(h.risk * 100)}%</div>
                                <div className="text-[8px] uppercase font-bold tracking-widest">{h.compromised ? 'Alert' : 'Clean'}</div>
                            </div>
                        )
                    })}
                </div>
              </Card>

            </div>
          )}
        </div>
      </main>
    </div>
  )
}

// ---------- UI Sub-Components ----------
function Card({ title, subtitle, icon, children }: any) { 
  return (
    <div className="bg-[#111113] border border-white/5 rounded-2xl p-6 shadow-xl relative overflow-hidden">
      <div className="flex items-center gap-2 mb-1">
        {icon && <div className="text-zinc-500">{icon}</div>}
        <div className="text-[12px] font-bold text-white tracking-wide">{title}</div>
      </div>
      {subtitle && <div className="text-[10px] text-zinc-500 mb-5">{subtitle}</div>}
      <div>{children}</div>
    </div> 
  )
}

function MetricCard({ label, value, sub, color, border }: any) { 
  return (
    <div className={`bg-[#18181b] border ${border} p-4 rounded-xl shadow-inner`}>
      <div className="text-[9px] font-bold text-zinc-500 uppercase tracking-widest">{label}</div>
      <div className={`text-3xl font-bold mt-1 ${color}`}>{value}</div>
      {sub && <div className="text-[9px] text-zinc-600 mt-1">{sub}</div>}
    </div> 
  )
}

function ActionButton({ icon, label, color, onClick }: any) {
    const colors: any = {
        red: 'bg-transparent border border-red-500/20 text-red-400 hover:bg-red-500/10',
        green: 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 hover:text-emerald-300',
        default: 'bg-[#27272a] border border-transparent text-zinc-300 hover:bg-zinc-700 hover:text-white'
    }
    return (
        <button onClick={onClick} className={`flex items-center gap-2 px-4 py-2 rounded-full text-[11px] font-medium transition-all ${colors[color || 'default']}`}>
            {icon} {label}
        </button>
    )
}

function SeverityPill({ sev, dimmed }: any) { 
  const c = { high: "bg-red-500/10 text-red-500 ring-1 ring-red-500/20", medium: "bg-amber-500/10 text-amber-500 ring-1 ring-amber-500/20", low: "bg-emerald-500/10 text-emerald-500 ring-1 ring-emerald-500/20" } as any; 
  return <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase ${c[sev]} ${dimmed ? 'opacity-30' : ''}`}>{sev}</span> 
}

function StatusPill({ status }: any) { 
  const c: any = { open: 'text-zinc-400 border-zinc-600', resolved: 'text-emerald-400 border-emerald-400/30 bg-emerald-400/10', investigating: 'text-cyan-400 border-cyan-400/30' };
  return <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded-full border tracking-wider ${c[status] || 'text-zinc-500 border-white/10'}`}>{status}</span> 
}

// ---------- Icons ----------
const ShieldIcon = () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
const GridIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
const ChartIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 3v18h18M18 9l-5 5-2-2-4 4"/></svg>
const LogsIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
const AlertIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01"/></svg>
const BoltIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
const SearchIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
const BanIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>
const IsolateIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6v6H9z"/></svg>
const IgnoreIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M9.88 9.88 3 16.76V21h4.24l6.88-6.88m-4.24-4.24L16.76 3V7.24l-6.88 6.88"/></svg>
const EscalateIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="m5 12 7-7 7 7M12 19V5"/></svg>
const CheckIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M20 6 9 17l-5-5"/></svg>