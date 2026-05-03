import React, { useState, useEffect } from 'react';
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';
import { fetchMonthlyReports, fetchStats, generateMonthlyReport, getMonthlyReportDownloadUrl } from '../lib/api';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import { CATEGORY_LABELS, SEVERITY_LABELS } from '../lib/constants';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6'];

function StatCard({ label, value, sub, color = 'text-white' }) {
  return (
    <div className="card p-5">
      <p className="text-gray-400 text-sm mb-1">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-gray-500 text-xs mt-1">{sub}</p>}
    </div>
  );
}

export default function StatsView() {
  const [stats, setStats] = useState(null);
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [reportMonth, setReportMonth] = useState(() => new Date().toISOString().slice(0, 7));

  const load = () => {
    setLoading(true);
    Promise.all([fetchStats(), fetchMonthlyReports()])
      .then(([statsPayload, reportsPayload]) => {
        setStats(statsPayload);
        setReports(reportsPayload.reports || []);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleGenerateReport = async () => {
    setGenerating(true);
    try {
      const { report } = await generateMonthlyReport({ month: reportMonth, force: true });
      setReports((current) => {
        const next = [report, ...current.filter((item) => item.id !== report.id)];
        return next.sort((a, b) => new Date(b.report_month) - new Date(a.report_month));
      });
    } catch (error) {
      console.error(error);
    } finally {
      setGenerating(false);
    }
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-gray-400">
      Chargement des statistiques…
    </div>
  );

  if (!stats) return null;

  const total = stats.byStatus.reduce((acc, r) => acc + parseInt(r.count), 0);
  const open  = stats.byStatus.find(r => r.status === 'open')?.count || 0;
  const critical = stats.bySeverity.find(r => r.severity === 'critical')?.count || 0;
  const latestReport = reports[0]?.summary || null;

  const categoryData = stats.byCategory.map(r => ({
    name: CATEGORY_LABELS[r.category]?.icon + ' ' + (CATEGORY_LABELS[r.category]?.label || r.category),
    value: parseInt(r.count),
  }));

  const severityData = stats.bySeverity.map(r => ({
    name: SEVERITY_LABELS[r.severity]?.label || r.severity,
    value: parseInt(r.count),
    fill: r.severity === 'critical' ? '#ef4444' :
          r.severity === 'high'     ? '#f97316' :
          r.severity === 'medium'   ? '#eab308' : '#22c55e',
  }));

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total incidents" value={total} sub="Tous statuts" />
        <StatCard label="Incidents ouverts" value={open} color="text-blue-400" />
        <StatCard label="Critiques actifs" value={critical} color="text-red-400" sub="Nécessitent action immédiate" />
        <StatCard
          label="Taux de résolution"
          value={total > 0 ? `${Math.round((stats.byStatus.find(r => r.status === 'closed')?.count || 0) / total * 100)}%` : '—'}
          color="text-green-400"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* By Category */}
        <div className="card p-5">
          <h3 className="text-gray-200 font-semibold mb-4">Par catégorie</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={categoryData} layout="vertical" margin={{ left: 10 }}>
              <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: '#d1d5db', fontSize: 11 }} width={130} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }}
                labelStyle={{ color: '#f9fafb' }}
              />
              <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* By Severity */}
        <div className="card p-5">
          <h3 className="text-gray-200 font-semibold mb-4">Par sévérité</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={90}
                paddingAngle={3}
                dataKey="value"
              >
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }}
              />
              <Legend
                formatter={(value) => <span style={{ color: '#d1d5db', fontSize: 12 }}>{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1.2fr_0.8fr] gap-6">
        <div className="card p-5">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h3 className="text-gray-200 font-semibold">Rapports mensuels PDF</h3>
              <p className="text-gray-500 text-xs mt-1">Génération planifiée côté backend, avec déclenchement manuel ici si nécessaire.</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="month"
                value={reportMonth}
                onChange={(e) => setReportMonth(e.target.value)}
                className="bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-gray-500"
              />
              <button
                onClick={handleGenerateReport}
                disabled={generating}
                className="btn-primary"
              >
                {generating ? 'Génération…' : 'Générer PDF'}
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {reports.length === 0 && (
              <div className="rounded-xl border border-dashed border-gray-700 p-4 text-sm text-gray-500">
                Aucun rapport généré pour le moment.
              </div>
            )}
            {reports.map((report) => (
              <div key={report.id} className="rounded-xl border border-gray-800 bg-gray-900/70 p-4 flex items-center justify-between gap-4">
                <div>
                  <p className="text-gray-100 text-sm font-medium">
                    {format(new Date(report.report_month), 'MMMM yyyy', { locale: fr })}
                  </p>
                  <p className="text-gray-500 text-xs mt-1">
                    {report.generated_at
                      ? `Généré le ${format(new Date(report.generated_at), 'PPp', { locale: fr })}`
                      : 'En attente de génération'}
                  </p>
                  {report.generated_by_name && (
                    <p className="text-gray-600 text-xs mt-1">par {report.generated_by_name}</p>
                  )}
                </div>
                <a
                  href={getMonthlyReportDownloadUrl(report.id)}
                  className="btn-ghost whitespace-nowrap"
                >
                  Télécharger
                </a>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5">
          <h3 className="text-gray-200 font-semibold mb-4">Dernier résumé mensuel</h3>
          {latestReport ? (
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Mois</span>
                <span className="text-gray-200">{latestReport.label || latestReport.month}</span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Incidents</span>
                <span className="text-gray-200">{latestReport.totals?.incidents ?? 0}</span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Taux de résolution</span>
                <span className="text-gray-200">{latestReport.totals?.resolution_rate ?? 0}%</span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Brèches SLA</span>
                <span className="text-gray-200">{latestReport.sla?.breached ?? 0}</span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Escalades auto</span>
                <span className="text-gray-200">{latestReport.sla?.escalated ?? 0}</span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Ack moyen</span>
                <span className="text-gray-200">{(latestReport.timings?.avg_ack_minutes ?? 0).toFixed(1)} min</span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <span className="text-gray-500">Résolution moyenne</span>
                <span className="text-gray-200">{(latestReport.timings?.avg_resolution_minutes ?? 0).toFixed(1)} min</span>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-gray-700 p-4 text-sm text-gray-500">
              Générez un premier rapport pour afficher le résumé mensuel ici.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
