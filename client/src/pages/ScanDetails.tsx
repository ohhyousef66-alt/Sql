import { useRoute } from "wouter";
import { useScan, useScanVulnerabilities, useScanLogs, useTrafficLogs, useExportReport, useCancelScan, useChildScans } from "@/hooks/use-scans";
import { Link } from "wouter";
import { Layout } from "@/components/Layout";
import { StatusBadge, ScanStatus } from "@/components/StatusBadge";
import { SeverityBadge } from "@/components/SeverityBadge";
import { LiveConsole } from "@/components/LiveConsole";
import DataExplorer from "@/components/DataExplorer";
import { 
  AlertTriangle, Download, RefreshCw, ChevronRight, Globe, 
  FileText, Activity, ShieldCheck, Bug, Terminal, Check, HelpCircle,
  Link2, Zap, ArrowRight, XCircle, Network, FolderSearch, Radio, List, Database
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import type { VerificationStatus } from "@shared/schema";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend } from "recharts";
import { useState } from "react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

interface AttackChainLink {
  vulnId: number;
  vulnType: string;
  severity: string;
  description: string;
  order: number;
}

interface AttackChain {
  id: string;
  name: string;
  description: string;
  overallSeverity: "Critical" | "High" | "Medium";
  exploitability: "Easy" | "Moderate" | "Complex";
  impact: string;
  attackFlow: string;
  links: AttackChainLink[];
}

function ChainSeverityBadge({ severity }: { severity: "Critical" | "High" | "Medium" }) {
  const styles = {
    Critical: "bg-red-500 text-white",
    High: "bg-orange-500 text-white",
    Medium: "bg-yellow-500 text-black",
  };
  
  return (
    <Badge className={cn("font-bold", styles[severity])} data-testid={`badge-chain-severity-${severity.toLowerCase()}`}>
      {severity}
    </Badge>
  );
}

function ExploitabilityBadge({ exploitability }: { exploitability: "Easy" | "Moderate" | "Complex" }) {
  const styles = {
    Easy: "bg-red-500/10 text-red-500 border-red-500/30",
    Moderate: "bg-yellow-500/10 text-yellow-500 border-yellow-500/30",
    Complex: "bg-green-500/10 text-green-500 border-green-500/30",
  };
  
  return (
    <Badge variant="outline" className={cn("text-xs", styles[exploitability])} data-testid={`badge-exploitability-${exploitability.toLowerCase()}`}>
      {exploitability} to exploit
    </Badge>
  );
}

function AttackChainCard({ chain }: { chain: AttackChain }) {
  return (
    <div className="border border-red-500/30 rounded-lg bg-red-500/5 p-4 space-y-4" data-testid={`card-attack-chain-${chain.id}`}>
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/10 rounded-lg">
            <Link2 className="w-5 h-5 text-red-500" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/50">
                <Zap className="w-3 h-3 mr-1" />
                Attack Chain Detected
              </Badge>
              <ChainSeverityBadge severity={chain.overallSeverity} />
            </div>
            <h4 className="font-bold text-lg text-foreground mt-1">{chain.name}</h4>
          </div>
        </div>
        <ExploitabilityBadge exploitability={chain.exploitability} />
      </div>
      
      <div className="space-y-3">
        <div className="bg-black/30 rounded-lg p-3 border border-border/50">
          <h5 className="text-xs uppercase text-muted-foreground font-bold mb-2">Attack Flow</h5>
          <div className="space-y-2">
            {chain.links.map((link, index) => (
              <div key={link.vulnId} className="flex items-center gap-2 text-sm" data-testid={`chain-step-${link.order}`}>
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary text-primary-foreground text-xs font-bold">
                  {link.order}
                </span>
                <SeverityBadge severity={link.severity} className="w-16" />
                <span className="text-foreground font-medium">{link.vulnType}</span>
                {index < chain.links.length - 1 && (
                  <ArrowRight className="w-4 h-4 text-muted-foreground" />
                )}
              </div>
            ))}
          </div>
        </div>
        
        <div className="bg-orange-500/5 border border-orange-500/30 rounded-lg p-3">
          <h5 className="text-xs uppercase text-orange-500 font-bold mb-1 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" />
            Impact
          </h5>
          <p className="text-sm text-foreground">{chain.impact}</p>
        </div>
        
        <div>
          <h5 className="text-xs uppercase text-muted-foreground font-bold mb-1">Description</h5>
          <p className="text-sm text-muted-foreground">{chain.description}</p>
        </div>
      </div>
    </div>
  );
}

function getConfidenceColor(confidence: number): { bg: string; text: string; label: string } {
  if (confidence >= 90) {
    return { bg: "bg-green-500/10", text: "text-green-500", label: "CONFIRMED" };
  } else if (confidence >= 70) {
    return { bg: "bg-yellow-500/10", text: "text-yellow-500", label: "POTENTIAL (high)" };
  } else {
    return { bg: "bg-orange-500/10", text: "text-orange-500", label: "POTENTIAL (low)" };
  }
}

function VerificationBadge({ status, confidence }: { status: string; confidence: number }) {
  const isConfirmed = status === "confirmed";
  
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 font-mono text-xs",
        isConfirmed
          ? "bg-green-500/10 text-green-500 border-green-500/30"
          : "bg-yellow-500/10 text-yellow-500 border-yellow-500/30"
      )}
      data-testid={`badge-verification-${isConfirmed ? 'confirmed' : 'potential'}`}
    >
      {isConfirmed ? <Check className="w-3 h-3" /> : <HelpCircle className="w-3 h-3" />}
      {isConfirmed ? "CONFIRMED" : "POTENTIAL"}
    </Badge>
  );
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  const colors = getConfidenceColor(confidence);
  
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-mono",
        colors.bg,
        colors.text
      )}
      data-testid="badge-confidence"
    >
      {confidence}%
    </span>
  );
}

interface CrawlStats {
  urlsDiscovered?: number;
  formsFound?: number;
  parametersFound?: number;
  apiEndpoints?: number;
  depth?: number;
  jsFilesAnalyzed?: number;
  authEndpointsFound?: number;
  webSocketEndpoints?: number;
  formWorkflowsDetected?: number;
  sensitiveEndpointsFound?: number;
}

interface LogEntry {
  id: number;
  level: string;
  message: string;
  timestamp: Date | null | string;
}

interface TrafficEntry {
  id: number;
  scanId?: number;
  requestUrl: string;
  requestMethod: string;
  requestHeaders?: Record<string, string> | null;
  requestPayload?: string | null;
  parameterName?: string | null;
  payloadType?: string | null;
  encodingUsed?: string | null;
  responseStatus?: number | null;
  responseTime?: number | null;
  responseSize?: number | null;
  responseSnippet?: string | null;
  detectionResult?: string | null;
  confidenceScore?: number | null;
  timestamp: Date | null | string;
}

function TrafficTab({ trafficLogs, scanStatus }: { trafficLogs: TrafficEntry[]; scanStatus: string }) {
  const getStatusColor = (status?: number | null) => {
    if (!status) return "text-muted-foreground";
    if (status >= 500) return "text-red-500";
    if (status >= 400) return "text-orange-500";
    if (status >= 300) return "text-yellow-500";
    if (status >= 200) return "text-green-500";
    return "text-muted-foreground";
  };

  const getResultColor = (result?: string | null) => {
    if (!result) return "";
    if (result.toLowerCase().includes("detected") || result.toLowerCase().includes("confirmed")) return "bg-red-500/10 text-red-500 border-red-500/30";
    if (result.toLowerCase().includes("potential")) return "bg-yellow-500/10 text-yellow-500 border-yellow-500/30";
    if (result.toLowerCase().includes("blocked")) return "bg-orange-500/10 text-orange-500 border-orange-500/30";
    return "bg-muted/50 text-muted-foreground";
  };

  return (
    <div className="space-y-4" data-testid="section-traffic">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="text-sm text-muted-foreground">
          Showing {trafficLogs.length} request{trafficLogs.length !== 1 ? 's' : ''} with payloads and responses
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-muted/30">
          <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <Radio className="w-4 h-4" />
            SQL Injection Traffic Log
          </h3>
        </div>
        
        <div className="max-h-[600px] overflow-y-auto">
          {trafficLogs.length > 0 ? (
            trafficLogs.map((log, idx) => (
              <div 
                key={log.id || idx} 
                className={cn(
                  "px-4 py-3 border-b border-border/50 last:border-0 hover:bg-muted/30 transition-colors",
                  log.detectionResult?.toLowerCase().includes("detected") && "bg-red-500/5"
                )}
                data-testid={`traffic-entry-${idx}`}
              >
                <div className="flex items-start gap-3">
                  <div className="flex flex-col items-center shrink-0">
                    <Badge 
                      variant="outline" 
                      className={cn("font-mono text-xs", log.requestMethod === "POST" ? "bg-blue-500/10 text-blue-500 border-blue-500/30" : "bg-green-500/10 text-green-500 border-green-500/30")}
                    >
                      {log.requestMethod}
                    </Badge>
                    <span className={cn("text-xs font-mono mt-1", getStatusColor(log.responseStatus))}>
                      {log.responseStatus || "---"}
                    </span>
                  </div>
                  
                  <div className="flex-1 min-w-0 space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <code className="text-xs font-mono text-foreground truncate max-w-full">{log.requestUrl}</code>
                      {log.responseTime && (
                        <span className="text-xs text-muted-foreground">{log.responseTime}ms</span>
                      )}
                    </div>
                    
                    {log.parameterName && (
                      <div className="flex items-center gap-2 text-xs">
                        <span className="text-muted-foreground">Param:</span>
                        <code className="bg-primary/10 text-primary px-1 rounded">{log.parameterName}</code>
                        {log.payloadType && (
                          <>
                            <span className="text-muted-foreground">|</span>
                            <span className="text-muted-foreground">{log.payloadType}</span>
                          </>
                        )}
                        {log.encodingUsed && log.encodingUsed !== "none" && (
                          <>
                            <span className="text-muted-foreground">|</span>
                            <span className="text-yellow-500">{log.encodingUsed}</span>
                          </>
                        )}
                      </div>
                    )}
                    
                    {log.requestPayload && (
                      <div className="bg-black/50 rounded p-2 overflow-x-auto">
                        <code className="text-xs font-mono text-red-400 whitespace-pre-wrap break-all">
                          {log.requestPayload.length > 200 ? log.requestPayload.substring(0, 200) + "..." : log.requestPayload}
                        </code>
                      </div>
                    )}
                    
                    {log.responseSnippet && (
                      <div className="bg-muted/30 rounded p-2 overflow-x-auto border border-border/50">
                        <code className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all">
                          {log.responseSnippet.length > 300 ? log.responseSnippet.substring(0, 300) + "..." : log.responseSnippet}
                        </code>
                      </div>
                    )}
                    
                    {log.detectionResult && (
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={cn("text-xs", getResultColor(log.detectionResult))}>
                          {log.detectionResult}
                        </Badge>
                        {log.confidenceScore !== null && log.confidenceScore !== undefined && (
                          <span className="text-xs font-mono text-muted-foreground">
                            Confidence: {log.confidenceScore}%
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                  
                  <div className="text-xs text-muted-foreground shrink-0">
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "-"}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="px-4 py-12 text-center text-muted-foreground">
              {scanStatus === 'scanning' ? (
                <>
                  <Activity className="w-8 h-8 mx-auto mb-2 animate-pulse" />
                  Waiting for SQL injection requests...
                </>
              ) : (
                <>
                  <Radio className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  No traffic logs available
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DiscoveryTab({ scan, logs }: { scan: any; logs: LogEntry[] }) {
  const crawlStats: CrawlStats = scan.crawlStats || {};
  
  const crawlerLogs = logs.filter(log => 
    log.message.includes('[Crawler]') || 
    log.message.includes('Discovered') ||
    log.message.includes('Found') ||
    log.message.includes('discovered')
  );

  const urlLogs = crawlerLogs.filter(log => 
    log.message.includes('Depth') || 
    log.message.includes('links') ||
    log.message.includes('forms')
  );

  return (
    <div className="space-y-6" data-testid="section-discovery">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-card border border-border rounded-lg p-4" data-testid="stat-urls">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-4 h-4 text-primary" />
            <span className="text-xs uppercase text-muted-foreground font-bold">URLs</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{crawlStats.urlsDiscovered || 0}</div>
          <div className="text-xs text-muted-foreground">discovered</div>
        </div>
        
        <div className="bg-card border border-border rounded-lg p-4" data-testid="stat-forms">
          <div className="flex items-center gap-2 mb-2">
            <FileText className="w-4 h-4 text-primary" />
            <span className="text-xs uppercase text-muted-foreground font-bold">Forms</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{crawlStats.formsFound || 0}</div>
          <div className="text-xs text-muted-foreground">found</div>
        </div>
        
        <div className="bg-card border border-border rounded-lg p-4" data-testid="stat-params">
          <div className="flex items-center gap-2 mb-2">
            <Network className="w-4 h-4 text-primary" />
            <span className="text-xs uppercase text-muted-foreground font-bold">Parameters</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{crawlStats.parametersFound || 0}</div>
          <div className="text-xs text-muted-foreground">detected</div>
        </div>
        
        <div className="bg-card border border-border rounded-lg p-4" data-testid="stat-api">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-4 h-4 text-primary" />
            <span className="text-xs uppercase text-muted-foreground font-bold">API Endpoints</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{crawlStats.apiEndpoints || 0}</div>
          <div className="text-xs text-muted-foreground">identified</div>
        </div>
      </div>

      {crawlStats.depth !== undefined && (
        <div className="bg-muted/30 border border-border/50 rounded-lg p-4">
          <div className="flex items-center gap-4 flex-wrap text-sm">
            <div><span className="text-muted-foreground">Max Depth:</span> <span className="font-bold">{crawlStats.depth}</span></div>
            {crawlStats.jsFilesAnalyzed !== undefined && (
              <div><span className="text-muted-foreground">JS Files:</span> <span className="font-bold">{crawlStats.jsFilesAnalyzed}</span></div>
            )}
            {crawlStats.sensitiveEndpointsFound !== undefined && crawlStats.sensitiveEndpointsFound > 0 && (
              <div className="text-yellow-500"><span className="text-muted-foreground">Sensitive:</span> <span className="font-bold">{crawlStats.sensitiveEndpointsFound}</span></div>
            )}
            {crawlStats.authEndpointsFound !== undefined && crawlStats.authEndpointsFound > 0 && (
              <div><span className="text-muted-foreground">Auth Endpoints:</span> <span className="font-bold">{crawlStats.authEndpointsFound}</span></div>
            )}
          </div>
        </div>
      )}

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-muted/30">
          <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <FolderSearch className="w-4 h-4" />
            Crawl Activity ({urlLogs.length} entries)
          </h3>
        </div>
        <div className="max-h-96 overflow-y-auto font-mono text-xs">
          {urlLogs.length > 0 ? (
            urlLogs.map((log, idx) => (
              <div 
                key={log.id || idx} 
                className={cn(
                  "px-4 py-2 border-b border-border/50 last:border-0",
                  log.level === 'error' && "bg-red-500/5 text-red-400",
                  log.level === 'warn' && "bg-yellow-500/5 text-yellow-400",
                  log.level === 'success' && "bg-green-500/5 text-green-400",
                )}
                data-testid={`log-entry-${idx}`}
              >
                <span className="text-muted-foreground">{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "-"}</span>
                {' '}
                <span className={cn(
                  log.message.includes('Depth 0') && "text-primary font-bold",
                  log.message.includes('Depth 1') && "text-primary",
                  log.message.includes('links') && "text-blue-400",
                  log.message.includes('forms') && "text-green-400",
                )}>
                  {log.message}
                </span>
              </div>
            ))
          ) : (
            <div className="px-4 py-8 text-center text-muted-foreground">
              {scan.status === 'scanning' ? (
                <>
                  <Activity className="w-8 h-8 mx-auto mb-2 animate-pulse" />
                  Waiting for crawler activity...
                </>
              ) : (
                <>
                  <FolderSearch className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  No crawler logs available
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ScanDetails() {
  const [, params] = useRoute("/scans/:id");
  const scanId = parseInt(params?.id || "0");
  const { data: scan, isLoading: isScanLoading } = useScan(scanId);
  const { data: vulnerabilities } = useScanVulnerabilities(scanId);
  const { data: logs } = useScanLogs(scanId);
  const { mutate: exportReport, isPending: isExporting } = useExportReport();
  const { mutate: cancelScan, isPending: isCancelling } = useCancelScan();
  
  const [activeTab, setActiveTab] = useState<"findings" | "discovery" | "traffic" | "logs" | "data">("findings");
  const { data: trafficLogs } = useTrafficLogs(scanId);
  
  // Fetch child scans if this is a batch parent
  const { data: childScans } = useChildScans(scanId, scan?.isParent || scan?.status === "batch_parent");

  if (isScanLoading || !scan) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-[50vh]">
          <div className="flex flex-col items-center gap-4">
             <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
             <p className="text-muted-foreground">Retrieving scan data...</p>
          </div>
        </div>
      </Layout>
    );
  }

  // Chart Data preparation
  const severityCounts = {
    Critical: vulnerabilities?.filter(v => v.severity.toLowerCase() === 'critical').length || 0,
    High: vulnerabilities?.filter(v => v.severity.toLowerCase() === 'high').length || 0,
    Medium: vulnerabilities?.filter(v => v.severity.toLowerCase() === 'medium').length || 0,
    Low: vulnerabilities?.filter(v => v.severity.toLowerCase() === 'low').length || 0,
    Info: vulnerabilities?.filter(v => v.severity.toLowerCase() === 'info').length || 0,
    Informational: vulnerabilities?.filter(v => v.severity.toLowerCase() === 'informational').length || 0,
  };

  const chartData = Object.entries(severityCounts)
    .filter(([_, value]) => value > 0)
    .map(([name, value]) => ({ name, value }));

  const severityColors: Record<string, string> = {
    Critical: "#ef4444", // red-500
    High: "#f97316", // orange-500
    Medium: "#eab308", // yellow-500
    Low: "#3b82f6", // blue-500
    Info: "#9ca3af", // gray-400
    Informational: "#0ea5e9", // sky-500
  };
  
  // Get attack chains from scan data
  const attackChains: AttackChain[] = (scan.attackChains as AttackChain[]) || [];

  return (
    <Layout>
      <div className="space-y-6">
        
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-border pb-6">
          <div className="space-y-2">
             <div className="flex items-center gap-2 text-sm text-muted-foreground font-mono">
                <Globe size={14} /> 
                <span>TARGET</span>
             </div>
             <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-foreground break-all">{scan.targetUrl}</h1>
             <div className="flex items-center gap-3">
               <StatusBadge status={scan.status as ScanStatus} />
               <span className="text-sm text-muted-foreground font-mono">ID: {scan.id}</span>
             </div>
          </div>

          <div className="flex items-center gap-3">
             {scan.status === 'scanning' && (
               <button 
                 onClick={() => {
                   if (window.confirm("Are you sure you want to cancel this scan?")) {
                     cancelScan(scan.id);
                   }
                 }} 
                 disabled={isCancelling}
                 className="
                   flex items-center gap-2 px-4 py-2 rounded-lg border border-red-500/30 bg-red-500/5 text-red-500
                   hover:bg-red-500/10 transition-colors
                   disabled:opacity-50 disabled:cursor-not-allowed
                 "
                 data-testid="button-cancel-scan"
               >
                  {isCancelling ? <Activity className="w-4 h-4 animate-spin" /> : <XCircle className="w-4 h-4" />}
                  Cancel Scan
               </button>
             )}
             <button 
               onClick={() => exportReport(scan.id)} 
               disabled={isExporting || scan.status === 'scanning'}
               className="
                 flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-card 
                 hover:bg-accent hover:text-accent-foreground transition-colors
                 disabled:opacity-50 disabled:cursor-not-allowed
               "
             >
                {isExporting ? <Activity className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                Export Report
             </button>
          </div>
        </div>

        {/* Batch Scan Children Section */}
        {(scan.isParent || scan.status === "batch_parent") && childScans && childScans.length > 0 && (
          <div className="bg-card border border-border rounded-xl p-6 shadow-lg" data-testid="section-batch-children">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold flex items-center gap-2">
                <List className="w-5 h-5 text-primary" />
                Batch Scan Progress ({childScans.filter(c => c.status === 'completed').length}/{childScans.length} complete)
              </h3>
              <Badge variant="outline" className="font-mono text-xs">
                {childScans.length} targets
              </Badge>
            </div>
            
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {childScans.map((child: any, idx: number) => {
                const childVulnCount = child.summary?.critical + child.summary?.high + child.summary?.medium + child.summary?.low || 0;
                return (
                  <Link 
                    key={child.id}
                    href={`/scans/${child.id}`}
                    className="flex items-center justify-between p-3 bg-muted/30 rounded-lg hover:bg-muted/50 transition-colors group"
                    data-testid={`batch-child-${idx}`}
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <span className="text-xs font-mono text-muted-foreground">#{child.id}</span>
                      <span className="text-sm font-mono truncate text-foreground group-hover:text-primary transition-colors">
                        {child.targetUrl}
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      {child.status === 'scanning' && (
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-20 bg-muted rounded-full overflow-hidden">
                            <div className="h-full bg-primary transition-all duration-300" style={{ width: `${child.progress || 0}%` }} />
                          </div>
                          <span className="text-xs font-mono text-primary">{child.progress || 0}%</span>
                        </div>
                      )}
                      {childVulnCount > 0 && (
                        <Badge variant="destructive" className="text-xs">
                          {childVulnCount} vuln{childVulnCount !== 1 ? 's' : ''}
                        </Badge>
                      )}
                      <StatusBadge status={child.status as ScanStatus} />
                      <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        )}

        {/* Progress Section (Only if running) */}
        {scan.status === 'scanning' && (
           <div className="bg-card border border-border rounded-xl p-6 relative overflow-hidden shadow-lg" data-testid="section-scan-progress">
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary/50 to-transparent animate-scan-line" />
              
              {/* SQL-Only Engine Header */}
              <div className="flex items-center justify-between mb-4">
                 <h3 className="font-bold flex items-center gap-2 text-primary">
                    <Activity className="w-5 h-5 animate-pulse" /> SQL Injection Detection in progress...
                 </h3>
                 <Badge variant="outline" className="font-mono text-xs bg-primary/10 text-primary border-primary/30" data-testid="badge-current-phase">
                    {scan.progressMetrics?.currentPhase?.replace(/_/g, ' ').toUpperCase() || "INITIALIZING"}
                 </Badge>
              </div>
              
              {/* Phase Description */}
              {scan.progressMetrics?.phaseDescription && (
                 <p className="text-sm text-foreground mb-4 bg-muted/50 rounded-lg px-3 py-2" data-testid="text-phase-description">
                    {scan.progressMetrics.phaseDescription}
                 </p>
              )}
              
              {/* WAR ROOM: Real-Time Attack Telemetry */}
              <div className="bg-red-500/5 border border-red-500/30 rounded-lg p-3 mb-4" data-testid="section-war-room">
                 <div className="flex items-center gap-2 mb-3">
                    <Zap className="w-4 h-4 text-red-500 animate-pulse" />
                    <span className="text-xs uppercase font-bold text-red-500">WAR ROOM - LIVE ATTACK TELEMETRY</span>
                 </div>
                 <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {/* RPS */}
                    <div className="bg-black/30 rounded-lg p-2 border border-red-500/20" data-testid="metric-rps">
                       <div className="text-xs uppercase text-red-400 font-bold mb-1">RPS</div>
                       <div className="text-2xl font-mono font-bold text-red-500">
                          {scan.progressMetrics?.rps?.toFixed(1) || "0.0"}
                       </div>
                       <div className="text-xs text-muted-foreground">req/sec</div>
                    </div>
                    
                    {/* Payload Queue */}
                    <div className="bg-black/30 rounded-lg p-2 border border-orange-500/20" data-testid="metric-queue">
                       <div className="text-xs uppercase text-orange-400 font-bold mb-1">QUEUE</div>
                       <div className="text-lg font-mono font-bold text-orange-500">
                          {scan.progressMetrics?.payloadsSent || 0}/{scan.progressMetrics?.totalPayloadsInQueue || 0}
                       </div>
                       <div className="text-xs text-muted-foreground">sent/total</div>
                    </div>
                    
                    {/* Current Parameter */}
                    <div className="bg-black/30 rounded-lg p-2 border border-cyan-500/20" data-testid="metric-current-param">
                       <div className="text-xs uppercase text-cyan-400 font-bold mb-1">FUZZING</div>
                       <div className="text-sm font-mono font-bold text-cyan-500 truncate" title={scan.progressMetrics?.currentParameter || "-"}>
                          {scan.progressMetrics?.currentParameter || "-"}
                       </div>
                       <div className="text-xs text-muted-foreground truncate" title={scan.progressMetrics?.currentUrl || ""}>
                          {scan.progressMetrics?.currentUrl ? new URL(scan.progressMetrics.currentUrl).pathname.slice(0, 30) : "-"}
                       </div>
                    </div>
                    
                    {/* Blocks */}
                    <div className="bg-black/30 rounded-lg p-2 border border-yellow-500/20" data-testid="metric-blocks">
                       <div className="text-xs uppercase text-yellow-400 font-bold mb-1">BLOCKS</div>
                       <div className="text-2xl font-mono font-bold text-yellow-500">
                          {scan.progressMetrics?.blocksEncountered || 0}
                       </div>
                       <div className="text-xs text-muted-foreground">WAF/CAPTCHA</div>
                    </div>
                 </div>
              </div>
              
              {/* LIVE PAYLOAD VIEW - Elite Status */}
              <div className="bg-purple-500/5 border border-purple-500/30 rounded-lg p-3 mb-4" data-testid="section-live-payload">
                 <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                       <Terminal className="w-4 h-4 text-purple-500 animate-pulse" />
                       <span className="text-xs uppercase font-bold text-purple-500">LIVE PAYLOAD VIEW</span>
                    </div>
                    <div className="flex items-center gap-2">
                       {scan.progressMetrics?.detectedDbType && scan.progressMetrics.detectedDbType !== 'unknown' && (
                          <Badge variant="outline" className="text-xs bg-purple-500/10 text-purple-400 border-purple-500/30">
                             {scan.progressMetrics.detectedDbType.toUpperCase()}
                          </Badge>
                       )}
                       {scan.progressMetrics?.detectedContext && scan.progressMetrics.detectedContext !== 'unknown' && (
                          <Badge variant="outline" className="text-xs bg-cyan-500/10 text-cyan-400 border-cyan-500/30">
                             CTX: {scan.progressMetrics.detectedContext}
                          </Badge>
                       )}
                    </div>
                 </div>
                 
                 {/* Current SQL Payload */}
                 <div className="bg-black/40 rounded-lg p-3 font-mono text-sm border border-purple-500/20 mb-2">
                    <div className="flex items-center justify-between mb-1">
                       <span className="text-xs text-purple-400 uppercase font-bold">
                          {scan.progressMetrics?.currentPayloadType || 'PROBE'}
                       </span>
                       <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">CONFIDENCE:</span>
                          <span className={cn(
                             "text-sm font-bold",
                             (scan.progressMetrics?.currentConfidence || 0) >= 90 ? "text-red-500" :
                             (scan.progressMetrics?.currentConfidence || 0) >= 70 ? "text-orange-500" :
                             (scan.progressMetrics?.currentConfidence || 0) >= 50 ? "text-yellow-500" : "text-muted-foreground"
                          )}>
                             {scan.progressMetrics?.currentConfidence || 0}%
                          </span>
                       </div>
                    </div>
                    <code className="text-purple-300 break-all leading-relaxed block max-h-20 overflow-y-auto">
                       {scan.progressMetrics?.currentPayload || "Initializing payload engine..."}
                    </code>
                 </div>
              </div>
              
              {/* Adaptive Testing Metrics */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4" data-testid="section-adaptive-metrics">
                 {/* Adaptive Concurrency */}
                 <div className="bg-green-500/5 rounded-lg p-2 border border-green-500/20">
                    <div className="text-xs uppercase text-green-400 font-bold mb-1">THREADS</div>
                    <div className="text-xl font-mono font-bold text-green-500">
                       {scan.progressMetrics?.adaptiveConcurrency || scan.threads || 10}
                    </div>
                    <div className="text-xs text-muted-foreground">auto-scaling</div>
                 </div>
                 
                 {/* Success Rate */}
                 <div className="bg-blue-500/5 rounded-lg p-2 border border-blue-500/20">
                    <div className="text-xs uppercase text-blue-400 font-bold mb-1">SUCCESS</div>
                    <div className="text-xl font-mono font-bold text-blue-500">
                       {(scan.progressMetrics?.successRate || 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-muted-foreground">rate</div>
                 </div>
                 
                 {/* Parameters Skipped */}
                 <div className="bg-amber-500/5 rounded-lg p-2 border border-amber-500/20">
                    <div className="text-xs uppercase text-amber-400 font-bold mb-1">SKIPPED</div>
                    <div className="text-xl font-mono font-bold text-amber-500">
                       {scan.progressMetrics?.parametersSkipped || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">secure params</div>
                 </div>
                 
                 {/* Coverage Per Hour */}
                 <div className="bg-indigo-500/5 rounded-lg p-2 border border-indigo-500/20">
                    <div className="text-xs uppercase text-indigo-400 font-bold mb-1">COVERAGE</div>
                    <div className="text-xl font-mono font-bold text-indigo-500">
                       {(scan.progressMetrics?.coveragePerHour || 0).toFixed(0)}
                    </div>
                    <div className="text-xs text-muted-foreground">tasks/hr</div>
                 </div>
                 
                 {/* Work Queue */}
                 <div className="bg-pink-500/5 rounded-lg p-2 border border-pink-500/20">
                    <div className="text-xs uppercase text-pink-400 font-bold mb-1">QUEUE</div>
                    <div className="text-xl font-mono font-bold text-pink-500">
                       {scan.progressMetrics?.workQueueSize || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">remaining</div>
                 </div>
              </div>
              
              {/* SQL Work Unit Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                 {/* SQL Payloads */}
                 <div className="bg-muted/30 rounded-lg p-3 border border-border/50" data-testid="metric-payloads">
                    <div className="text-xs uppercase text-muted-foreground font-bold mb-1">SQL Payloads</div>
                    <div className="flex items-baseline gap-1">
                       <span className="text-xl font-bold text-foreground">{scan.progressMetrics?.payloadsTested || 0}</span>
                       <span className="text-sm text-muted-foreground">/ {scan.progressMetrics?.payloadsDiscovered || 0}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                       {scan.progressMetrics?.payloadsRemaining || 0} remaining
                    </div>
                 </div>
                 
                 {/* SQL Parameters */}
                 <div className="bg-muted/30 rounded-lg p-3 border border-border/50" data-testid="metric-parameters">
                    <div className="text-xs uppercase text-muted-foreground font-bold mb-1">Parameters</div>
                    <div className="flex items-baseline gap-1">
                       <span className="text-xl font-bold text-foreground">{scan.progressMetrics?.parametersTested || 0}</span>
                       <span className="text-sm text-muted-foreground">/ {scan.progressMetrics?.parametersDiscovered || 0}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">SQL tested</div>
                 </div>
                 
                 {/* Endpoints */}
                 <div className="bg-muted/30 rounded-lg p-3 border border-border/50" data-testid="metric-urls">
                    <div className="text-xs uppercase text-muted-foreground font-bold mb-1">Endpoints</div>
                    <div className="flex items-baseline gap-1">
                       <span className="text-xl font-bold text-foreground">{scan.progressMetrics?.urlsTested || 0}</span>
                       <span className="text-sm text-muted-foreground">/ {scan.progressMetrics?.urlsDiscovered || 0}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">discovered</div>
                 </div>
                 
                 {/* Last Activity */}
                 <div className="bg-muted/30 rounded-lg p-3 border border-border/50" data-testid="metric-activity">
                    <div className="text-xs uppercase text-muted-foreground font-bold mb-1">Status</div>
                    <div className="text-sm font-mono text-foreground truncate">
                       {scan.progressMetrics?.lastActivity || "Starting..."}
                    </div>
                 </div>
              </div>
              
              {/* De-emphasized progress indicator */}
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                 <div className="h-1.5 flex-1 bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-primary/60 transition-all duration-500 ease-out" 
                      style={{ width: `${scan.progress || 0}%` }} 
                    />
                 </div>
                 <span className="font-mono shrink-0">{scan.progress || 0}%</span>
              </div>
           </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-full">
          
          {/* Main Content Area */}
          <div className="lg:col-span-2 space-y-6">
             {/* Tabs */}
             <div className="flex border-b border-border flex-wrap gap-1">
                <button 
                  onClick={() => setActiveTab('findings')}
                  className={cn(
                    "px-6 py-3 font-medium text-sm border-b-2 transition-colors flex items-center gap-2",
                    activeTab === 'findings' 
                      ? "border-primary text-primary" 
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                  data-testid="tab-findings"
                >
                   <Bug className="w-4 h-4" /> Findings ({vulnerabilities?.length || 0})
                </button>
                <button 
                  onClick={() => setActiveTab('discovery')}
                  className={cn(
                    "px-6 py-3 font-medium text-sm border-b-2 transition-colors flex items-center gap-2",
                    activeTab === 'discovery' 
                      ? "border-primary text-primary" 
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                  data-testid="tab-discovery"
                >
                   <FolderSearch className="w-4 h-4" /> Discovery
                </button>
                <button 
                  onClick={() => setActiveTab('traffic')}
                  className={cn(
                    "px-6 py-3 font-medium text-sm border-b-2 transition-colors flex items-center gap-2",
                    activeTab === 'traffic' 
                      ? "border-primary text-primary" 
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                  data-testid="tab-traffic"
                >
                   <Radio className="w-4 h-4" /> Traffic ({trafficLogs?.length || 0})
                </button>
                <button 
                  onClick={() => setActiveTab('logs')}
                  className={cn(
                    "px-6 py-3 font-medium text-sm border-b-2 transition-colors flex items-center gap-2",
                    activeTab === 'logs' 
                      ? "border-primary text-primary" 
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                  data-testid="tab-logs"
                >
                   <Terminal className="w-4 h-4" /> Live Logs
                </button>
                <button 
                  onClick={() => setActiveTab('data')}
                  className={cn(
                    "px-6 py-3 font-medium text-sm border-b-2 transition-colors flex items-center gap-2",
                    activeTab === 'data' 
                      ? "border-primary text-primary" 
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                  data-testid="tab-data"
                  title="SQLi Dumper - Extract database contents"
                >
                   <Database className="w-4 h-4" /> Data Dumper
                </button>
             </div>

             {activeTab === 'discovery' ? (
                <DiscoveryTab scan={scan} logs={logs || []} />
             ) : activeTab === 'traffic' ? (
                <TrafficTab trafficLogs={trafficLogs || []} scanStatus={scan.status} />
             ) : activeTab === 'findings' ? (
                <div className="space-y-6">
                   {/* Attack Chains Section */}
                   {attackChains.length > 0 && (
                     <div className="space-y-4" data-testid="section-attack-chains">
                        <div className="flex items-center gap-2">
                           <Link2 className="w-5 h-5 text-red-500" />
                           <h3 className="text-lg font-bold text-foreground">Attack Chains Detected ({attackChains.length})</h3>
                        </div>
                        <div className="space-y-4">
                           {attackChains.map((chain) => (
                              <AttackChainCard key={chain.id} chain={chain} />
                           ))}
                        </div>
                     </div>
                   )}
                   
                   {/* Vulnerabilities Section */}
                   {vulnerabilities && vulnerabilities.length > 0 ? (
                     <Accordion type="single" collapsible className="w-full space-y-3">
                        {vulnerabilities.map((vuln) => (
                           <AccordionItem 
                             key={vuln.id} 
                             value={`item-${vuln.id}`} 
                             className="border border-border rounded-lg bg-card px-4"
                           >
                              <AccordionTrigger className="hover:no-underline py-4">
                                 <div className="flex items-center gap-3 text-left w-full pr-4 flex-wrap">
                                    <SeverityBadge severity={vuln.severity} className="shrink-0 w-20" />
                                    <VerificationBadge 
                                       status={vuln.verificationStatus || "potential"} 
                                       confidence={vuln.confidence || 50} 
                                    />
                                    <div className="flex-1 min-w-0">
                                       <div className="flex items-center gap-2 flex-wrap">
                                          <h4 className="font-bold text-foreground">{vuln.type}</h4>
                                          <span className="text-muted-foreground">-</span>
                                          <ConfidenceBadge confidence={vuln.confidence || 50} />
                                       </div>
                                       <p className="text-xs text-muted-foreground font-mono truncate mt-0.5">{vuln.path || "/"}</p>
                                    </div>
                                 </div>
                              </AccordionTrigger>
                              <AccordionContent className="pb-4 pt-1 border-t border-border/50 space-y-4">
                                 <div className="mt-3">
                                    <strong className="text-muted-foreground block text-xs uppercase mb-1">URL</strong>
                                    <code className="bg-muted px-2 py-1 rounded text-primary font-mono text-xs break-all block">{vuln.url}</code>
                                 </div>
                                 <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                    <div>
                                       <strong className="text-muted-foreground block text-xs uppercase mb-1">Affected Parameter</strong>
                                       <code className="bg-muted px-2 py-1 rounded text-primary font-mono">{vuln.parameter || "N/A"}</code>
                                    </div>
                                    <div>
                                       <strong className="text-muted-foreground block text-xs uppercase mb-1">Vulnerability Type</strong>
                                       <span className="text-foreground">{vuln.type}</span>
                                    </div>
                                 </div>
                                 
                                 {vuln.payload && (
                                    <div>
                                       <strong className="text-muted-foreground block text-xs uppercase mb-1">Payload Used</strong>
                                       <pre className="bg-black/50 p-3 rounded border border-border overflow-x-auto text-xs font-mono text-red-400">
                                          {vuln.payload}
                                       </pre>
                                    </div>
                                 )}
                                 
                                 {vuln.description && (
                                     <div>
                                        <strong className="text-muted-foreground block text-xs uppercase mb-1">Description</strong>
                                        <p className="text-muted-foreground leading-relaxed">{vuln.description}</p>
                                     </div>
                                 )}

                                 {vuln.verificationDetails && (
                                     <div className="bg-primary/5 border border-primary/20 p-3 rounded">
                                        <strong className="text-primary block text-xs uppercase mb-1 flex items-center gap-1">
                                           {vuln.verificationStatus === "confirmed" ? (
                                             <Check className="w-3 h-3" />
                                           ) : (
                                             <HelpCircle className="w-3 h-3" />
                                           )}
                                           Verification Details
                                        </strong>
                                        <p className="text-muted-foreground text-sm font-mono">{vuln.verificationDetails}</p>
                                     </div>
                                 )}

                                 {vuln.remediation && (
                                     <div className="bg-green-500/5 border border-green-500/20 p-3 rounded">
                                        <strong className="text-green-500 block text-xs uppercase mb-1 flex items-center gap-1">
                                           <ShieldCheck className="w-3 h-3" /> Remediation
                                        </strong>
                                        <p className="text-muted-foreground text-sm">{vuln.remediation}</p>
                                     </div>
                                 )}
                              </AccordionContent>
                           </AccordionItem>
                        ))}
                     </Accordion>
                   ) : (
                     <div className="text-center py-12 border border-dashed border-border rounded-xl bg-card/50">
                        {scan.status === 'completed' ? (
                          <>
                             <ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-3" />
                             <h3 className="text-lg font-bold">No Vulnerabilities Found</h3>
                             <p className="text-muted-foreground">The target appears secure against the configured tests.</p>
                          </>
                        ) : (
                           <>
                             <Activity className="w-12 h-12 text-muted-foreground mx-auto mb-3 animate-pulse" />
                             <h3 className="text-lg font-bold">Waiting for results...</h3>
                             <p className="text-muted-foreground">Vulnerabilities will appear here as they are detected.</p>
                           </>
                        )}
                     </div>
                   )}
                </div>
             ) : activeTab === 'data' ? (
                <div className="space-y-6">
                   {vulnerabilities && vulnerabilities.length > 0 ? (
                      vulnerabilities.map((vuln) => (
                         vuln.verificationStatus === 'confirmed' && (
                            <DataExplorer 
                               key={vuln.id}
                               vulnerabilityId={vuln.id}
                               targetUrl={vuln.url}
                            />
                         )
                      ))
                   ) : (
                      <Card className="p-12">
                         <div className="text-center space-y-3">
                            <Database className="w-12 h-12 mx-auto text-muted-foreground/50" />
                            <h3 className="text-lg font-bold text-muted-foreground">No Vulnerabilities Found</h3>
                            <p className="text-sm text-muted-foreground/70">
                               Data dumping requires confirmed SQL injection vulnerabilities.
                            </p>
                         </div>
                      </Card>
                   )}
                </div>
             ) : (
                <LiveConsole logs={logs || []} height="600px" />
             )}
          </div>

          {/* Sidebar / Stats */}
          <div className="space-y-6">
             {/* Severity Chart */}
             <div className="bg-card border border-border rounded-xl p-6 shadow-lg">
                <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground mb-4">Vulnerability Distribution</h3>
                
                {chartData.length > 0 ? (
                  <div className="h-64 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={chartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={severityColors[entry.name] || "#8884d8"} stroke="rgba(0,0,0,0.5)" />
                          ))}
                        </Pie>
                        <RechartsTooltip 
                          contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', borderRadius: '8px' }}
                          itemStyle={{ color: '#fff' }}
                        />
                        <Legend verticalAlign="bottom" height={36} iconType="circle" />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                   <div className="h-64 flex items-center justify-center text-muted-foreground text-sm italic">
                      No data to visualize yet
                   </div>
                )}
             </div>

             {/* Scan Info */}
             <div className="bg-card border border-border rounded-xl p-6 shadow-lg">
                <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground mb-4">Scan Details</h3>
                <dl className="space-y-3 text-sm">
                   <div className="flex justify-between">
                      <dt className="text-muted-foreground">Started</dt>
                      <dd className="font-mono">{scan.startTime ? format(new Date(scan.startTime), "MMM d, HH:mm") : "-"}</dd>
                   </div>
                   <div className="flex justify-between">
                      <dt className="text-muted-foreground">Duration</dt>
                      <dd className="font-mono">
                         {scan.endTime && scan.startTime 
                            ? `${Math.round((new Date(scan.endTime).getTime() - new Date(scan.startTime).getTime()) / 1000)}s`
                            : scan.status === 'scanning' ? "Running..." : "-"
                         }
                      </dd>
                   </div>
                   <div className="border-t border-border/50 pt-3 flex justify-between">
                      <dt className="text-muted-foreground">Engine Status</dt>
                      <dd className="flex items-center gap-2">
                         <div className={cn("w-2 h-2 rounded-full", scan.status === 'scanning' ? "bg-green-500 animate-pulse" : "bg-gray-500")} />
                         {scan.status === 'scanning' ? "Online" : "Idle"}
                      </dd>
                   </div>
                   {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
                     <div className="border-t border-border/50 pt-3">
                        <dt className="text-muted-foreground text-xs uppercase mb-1">Completion Reason</dt>
                        <dd className={cn(
                          "text-sm font-medium",
                          scan.status === 'completed' ? "text-green-500" :
                          scan.status === 'failed' ? "text-red-500" : "text-amber-500"
                        )}>
                          {(scan as any).completionReason || 
                            (scan.status === 'completed' ? "Scan completed" : 
                             scan.status === 'failed' ? "Scan failed" : "Scan cancelled")}
                        </dd>
                     </div>
                   )}
                </dl>
             </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
