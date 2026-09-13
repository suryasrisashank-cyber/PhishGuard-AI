import React from 'react';
import PageHeader from '../components/ui/PageHeader.jsx';
import GlassCard from '../components/ui/GlassCard.jsx';
import { Shield, ExternalLink, Activity } from 'lucide-react';

const MITRE_FRAMEWORK = [
  {
    tactic: 'Initial Access (TA0001)',
    description: 'Adversary attempting to gain an initial foothold into the victim environment.',
    techniques: [
      {
        id: 'T1566',
        name: 'Phishing',
        evidencePattern: 'Urgent social engineering, credential lure keywords, forged brand sender address.',
      },
      {
        id: 'T1566.001',
        name: 'Spearphishing Attachment',
        evidencePattern: 'Weaponized script (.ps1, .vbs, .hta, .iso) attached to email payload.',
      },
      {
        id: 'T1566.002',
        name: 'Spearphishing Link',
        evidencePattern: 'Brand impersonation link, Punycode/homoglyph domain, or obfuscated redirect chain.',
      },
    ],
  },
  {
    tactic: 'Execution (TA0002)',
    description: 'Adversary attempting to run malicious code on an endpoint.',
    techniques: [
      {
        id: 'T1204.002',
        name: 'User Execution: Malicious File',
        evidencePattern: 'Executable dropper payload requiring victim double-click (scr, bat, exe, lnk).',
      },
      {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        evidencePattern: 'Static PowerShell, cmd.exe, or WScript invocation strings identified in file payload.',
      },
    ],
  },
  {
    tactic: 'Command & Control (TA0011)',
    description: 'Adversary communicating with systems under their control within a victim network.',
    techniques: [
      {
        id: 'T1071.001',
        name: 'Application Layer Protocol: Web Protocols',
        evidencePattern: 'HTTP/HTTPS beaconing to unclassified external domains or raw IPs in PCAP capture.',
      },
      {
        id: 'T1071.004',
        name: 'Application Layer Protocol: DNS',
        evidencePattern: 'Unusual DNS queries targeting suspicious TLDs or anomalous TXT record requests.',
      },
    ],
  },
  {
    tactic: 'Reconnaissance (TA0043)',
    description: 'Adversary gathering information to plan future target operations.',
    techniques: [
      {
        id: 'T1598.003',
        name: 'Phishing for Information: Spearphishing Link',
        evidencePattern: 'Harvesting forms collecting victim organizational structure or credentials.',
      },
    ],
  },
];

export default function MitreAttackPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="MITRE ATT&CK Enterprise Matrix"
        subtitle="Evidentiary technique mapping for phishing campaigns, weaponized payloads, and network telemetry."
      />

      <div className="space-y-6">
        {MITRE_FRAMEWORK.map((tactic) => (
          <GlassCard key={tactic.tactic} className="p-6 space-y-4">
            <div>
              <span className="text-[11px] font-mono text-cyber-blue uppercase tracking-wider">TACTIC</span>
              <h3 className="text-base font-semibold text-white mt-0.5">{tactic.tactic}</h3>
              <p className="text-xs text-slate-400 mt-1">{tactic.description}</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {tactic.techniques.map((tech) => (
                <div key={tech.id} className="p-3.5 rounded-lg bg-black/30 border border-white/5 space-y-2 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-cyber-blue">{tech.id}</span>
                      <a
                        href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-slate-500 hover:text-white transition"
                      >
                        <ExternalLink size={12} />
                      </a>
                    </div>
                    <h4 className="text-sm font-medium text-white mt-1">{tech.name}</h4>
                  </div>
                  <div className="mt-2 pt-2 border-t border-white/5 text-[11px] text-slate-400">
                    <span className="text-slate-500 block text-[10px] uppercase font-mono">Evidence Trigger:</span>
                    {tech.evidencePattern}
                  </div>
                </div>
              ))}
            </div>
          </GlassCard>
        ))}
      </div>
    </div>
  );
}
