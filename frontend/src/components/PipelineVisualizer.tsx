'use client';

import React from 'react';
import {
  Layers,
  KeyRound,
  FileSearch,
  Server,
  Radio,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Loader2,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { PipelineLane, PipelineLaneStatus } from '@/types/api';

interface PipelineVisualizerProps {
  lanes: PipelineLane[];
  targetDomain: string;
  onLaneClick?: (laneId: string) => void;
}

export const PipelineVisualizer: React.FC<PipelineVisualizerProps> = ({
  lanes,
  targetDomain,
  onLaneClick,
}) => {
  const getLaneIcon = (laneId: string) => {
    switch (laneId) {
      case 'crypto':
        return <KeyRound className="w-4 h-4 text-rose-400" />;
      case 'typosquat':
        return <FileSearch className="w-4 h-4 text-amber-400" />;
      case 'posture':
        return <Server className="w-4 h-4 text-sky-400" />;
      case 'threat_feeds':
        return <Radio className="w-4 h-4 text-emerald-400" />;
      default:
        return <Layers className="w-4 h-4 text-zinc-400" />;
    }
  };

  const getStatusBadge = (status: PipelineLaneStatus) => {
    switch (status) {
      case 'passed':
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/60">
            <CheckCircle2 className="w-3 h-3" />
            <span>CLEAN</span>
          </span>
        );
      case 'warning':
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono text-amber-400 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/60">
            <AlertTriangle className="w-3 h-3" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'failed':
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono text-rose-400 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-800/60">
            <XCircle className="w-3 h-3" />
            <span>THREAT DETECTED</span>
          </span>
        );
      case 'running':
      default:
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono text-sky-400 bg-sky-950/40 px-2 py-0.5 rounded border border-sky-800/60">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span>SCANNING</span>
          </span>
        );
    }
  };

  return (
    <div className="bento-card p-5 space-y-4">
      {/* Dispatcher Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-subtle gap-2">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-zinc-400" />
          <span className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Parallel Inspection Pipeline (4 Concurrent Workers)
          </span>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
          <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
            INGRESS: <span className="text-emerald-400">{targetDomain}</span>
          </span>
          <span className="text-zinc-600">→</span>
          <span className="text-zinc-400 text-[11px]">DISPATCHED IN 2ms</span>
        </div>
      </div>

      {/* The 4 Horizontal Lanes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
        {lanes.map((lane, index) => {
          const isError = lane.status === 'failed';
          const isWarn = lane.status === 'warning';

          return (
            <div
              key={lane.laneId}
              onClick={() => onLaneClick?.(lane.laneId)}
              className={`group cursor-pointer p-3.5 rounded-lg border transition-all duration-200 flex flex-col justify-between space-y-3 bg-ground/60 hover:bg-ground hover:border-zinc-700 active:scale-[0.99] ${
                isError
                  ? 'border-rose-900/50 hover:border-rose-700'
                  : isWarn
                  ? 'border-amber-900/50 hover:border-amber-700'
                  : 'border-border-subtle hover:border-zinc-700'
              }`}
            >
              {/* Lane Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-zinc-600 font-semibold">
                    0{index + 1}
                  </span>
                  {getLaneIcon(lane.laneId)}
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="flex items-center gap-1 text-[10px] font-mono text-zinc-500">
                    <Clock className="w-2.5 h-2.5" />
                    <span>{lane.latencyMs}ms</span>
                  </span>
                  {getStatusBadge(lane.status)}
                </div>
              </div>

              {/* Title & Badge */}
              <div className="space-y-1">
                <h4 className="font-mono text-xs font-semibold text-zinc-200 group-hover:text-zinc-100 flex items-center justify-between">
                  <span>{lane.title}</span>
                  <ArrowRight className="w-3 h-3 text-zinc-600 group-hover:text-zinc-300 transition-colors" />
                </h4>
                <div className="font-mono text-[11px] font-medium text-zinc-300 bg-zinc-900/90 px-2 py-0.5 rounded border border-zinc-800">
                  {lane.badge}
                </div>
              </div>

              {/* Deep Insight Text */}
              <p className="text-[11px] text-zinc-400 font-sans leading-relaxed line-clamp-2">
                {lane.insight}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
