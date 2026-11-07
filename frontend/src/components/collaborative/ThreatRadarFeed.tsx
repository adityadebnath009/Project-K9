'use client';

import React, { useState } from 'react';
import { Radio, ThumbsUp, ThumbsDown, CheckCircle, ShieldAlert, FileCode, Users } from 'lucide-react';
import { RadarIncident } from '@/types/api';

interface ThreatRadarFeedProps {
  incidents: RadarIncident[];
  onOpenStixModal: (bundle: Record<string, unknown>) => void;
  onSelectIncidentTarget?: (url: string) => void;
}

export const ThreatRadarFeed: React.FC<ThreatRadarFeedProps> = ({
  incidents: initialIncidents,
  onOpenStixModal,
  onSelectIncidentTarget,
}) => {
  const [incidents, setIncidents] = useState<RadarIncident[]>(initialIncidents);
  const [filter, setFilter] = useState<string>('ALL');

  const handleVote = (incidentId: string, voteType: 'confirm' | 'flag') => {
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id !== incidentId) return inc;
        if (inc.userVoted === voteType) return inc; // already voted same

        const wasConfirmed = inc.userVoted === 'confirm';
        const wasFlagged = inc.userVoted === 'flag';

        let newConfirm = inc.confirmVotes;
        let newFlag = inc.flagFalseVotes;

        if (voteType === 'confirm') {
          newConfirm += 1;
          if (wasFlagged) newFlag -= 1;
        } else {
          newFlag += 1;
          if (wasConfirmed) newConfirm -= 1;
        }

        const total = newConfirm + newFlag;
        const newConsensus = total > 0 ? Math.round((newConfirm / total) * 100) : 0;

        return {
          ...inc,
          confirmVotes: newConfirm,
          flagFalseVotes: newFlag,
          userVoted: voteType,
          consensusPercent: newConsensus,
        };
      })
    );
  };

  const filteredIncidents =
    filter === 'ALL' ? incidents : incidents.filter((i) => i.category.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-subtle gap-2">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-emerald-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Collaborative Threat Radar (Live Community Feed)
          </h3>
        </div>

        <div className="flex items-center gap-1 font-mono text-[11px]">
          {['ALL', 'eMudhra', 'Phishing', 'Config'].map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-2 py-0.5 rounded transition-colors ${
                filter === cat
                  ? 'bg-zinc-800 text-zinc-100 font-bold border border-zinc-700'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Stream */}
      <div className="space-y-3 font-mono text-xs max-h-[460px] overflow-y-auto pr-1">
        {filteredIncidents.map((incident) => {
          const isCritical = incident.severity === 'CRITICAL';

          return (
            <div
              key={incident.id}
              className="p-3.5 rounded-lg border border-border-subtle bg-ground/80 hover:border-zinc-700 transition-all space-y-2.5"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <div className="flex items-center gap-2 truncate">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${
                      isCritical
                        ? 'bg-rose-950 text-rose-300 border-rose-800'
                        : 'bg-amber-950 text-amber-300 border-amber-800'
                    }`}
                  >
                    {incident.category}
                  </span>
                  <button
                    type="button"
                    onClick={() => onSelectIncidentTarget?.(incident.url)}
                    className="font-bold text-zinc-200 hover:text-emerald-400 truncate text-left transition-colors"
                    title="Click to scan this target"
                  >
                    {incident.domain}
                  </button>
                </div>

                <span className="text-zinc-500 text-[11px] shrink-0">{incident.timestamp}</span>
              </div>

              {/* Consensus progress bar */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] text-zinc-400">
                  <span className="flex items-center gap-1">
                    <Users className="w-3 h-3 text-zinc-500" />
                    <span>Consensus: {incident.consensusPercent}% ({incident.confirmVotes + incident.flagFalseVotes} votes)</span>
                  </span>
                  <span>Reported by: {incident.reporter}</span>
                </div>
                <div className="w-full bg-zinc-900 rounded-full h-1.5 overflow-hidden border border-zinc-800">
                  <div
                    className="h-full bg-emerald-500 transition-all duration-300 rounded-full"
                    style={{ width: `${incident.consensusPercent}%` }}
                  />
                </div>
              </div>

              {/* Voting buttons & STIX download */}
              <div className="flex items-center justify-between pt-1">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleVote(incident.id, 'confirm')}
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] transition-all active:scale-[0.98] ${
                      incident.userVoted === 'confirm'
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                        : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border-zinc-800'
                    }`}
                  >
                    <ThumbsUp className="w-3 h-3" />
                    <span>Confirm ({incident.confirmVotes})</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleVote(incident.id, 'flag')}
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] transition-all active:scale-[0.98] ${
                      incident.userVoted === 'flag'
                        ? 'bg-rose-950 text-rose-300 border-rose-700'
                        : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border-zinc-800'
                    }`}
                  >
                    <ThumbsDown className="w-3 h-3" />
                    <span>False Positive ({incident.flagFalseVotes})</span>
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => onOpenStixModal(incident.stixBundle)}
                  className="flex items-center gap-1 text-[11px] text-zinc-400 hover:text-zinc-200 p-1 rounded hover:bg-zinc-800 transition-colors"
                >
                  <FileCode className="w-3.5 h-3.5 text-sky-400" />
                  <span className="hidden sm:inline">STIX 2.1</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
