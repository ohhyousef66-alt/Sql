import { useScans } from "@/hooks/use-scans";
import { Layout } from "@/components/Layout";
import { Link } from "wouter";
import { StatusBadge, ScanStatus } from "@/components/StatusBadge";
import { Plus, Search, AlertTriangle, ShieldCheck, Activity } from "lucide-react";
import { format } from "date-fns";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

export default function Home() {
  const { data: scans, isLoading, error } = useScans();

  // Filter out child scans (they should only appear under their parent batch scan)
  const visibleScans = scans?.filter(s => !(s as any).parentScanId) || [];
  
  // Calculate stats from visible scans only
  const totalScans = visibleScans.length;
  const activeScans = visibleScans.filter(s => s.status === 'scanning' || s.status === 'batch_parent').length;
  const criticalFound = visibleScans.reduce((acc, curr) => acc + (curr.summary?.critical || 0), 0);

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-[60vh]">
          <div className="flex flex-col items-center gap-4">
             <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
             <p className="text-muted-foreground animate-pulse">Establishing connection...</p>
          </div>
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout>
        <div className="bg-destructive/10 border border-destructive/50 text-destructive p-6 rounded-lg">
          <h2 className="text-xl font-bold flex items-center gap-2">
            <AlertTriangle /> Error Loading Scans
          </h2>
          <p className="mt-2 opacity-90">{error.message}</p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-8">
        
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-white font-display">Scan Operations</h1>
            <p className="text-muted-foreground mt-1">Manage and monitor your security assessments.</p>
          </div>
          
          <div className="flex items-center gap-3">
            <Link href="/scans/batch" className="
              inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm
              bg-muted text-foreground border border-border
              hover:bg-muted/80 transition-all active:scale-95
            " data-testid="link-batch-scan">
              <Plus size={18} />
              Batch Scan
            </Link>
            <Link href="/scans/new" className="
              inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm
              bg-primary text-primary-foreground shadow-[0_0_20px_-5px_hsl(var(--primary))]
              hover:shadow-[0_0_25px_-5px_hsl(var(--primary))] hover:bg-primary/90 
              transition-all active:scale-95
            " data-testid="link-new-scan">
              <Plus size={18} />
              New Scan
            </Link>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatCard 
            title="Active Scans" 
            value={activeScans} 
            icon={<Activity className="text-blue-500" />} 
            trend={activeScans > 0 ? "Running now" : "System idle"}
            trendColor={activeScans > 0 ? "text-blue-400" : "text-muted-foreground"}
          />
          <StatCard 
            title="Critical Vulns" 
            value={criticalFound} 
            icon={<AlertTriangle className="text-red-500" />} 
            trend="Total detected"
            trendColor="text-red-400"
          />
          <StatCard 
            title="Total Scans" 
            value={totalScans} 
            icon={<ShieldCheck className="text-green-500" />} 
            trend="All time"
            trendColor="text-muted-foreground"
          />
        </div>

        {/* Scan List */}
        <div className="bg-card rounded-xl border border-border shadow-lg overflow-hidden">
          <div className="p-4 border-b border-border flex items-center justify-between bg-muted/30">
            <h2 className="font-semibold text-lg flex items-center gap-2">
              <Search className="w-4 h-4 text-muted-foreground" />
              Recent Targets
            </h2>
            <span className="text-xs font-mono text-muted-foreground px-2 py-1 bg-background rounded border border-border">
              FILTER: ALL
            </span>
          </div>

          <div className="divide-y divide-border">
            {visibleScans.length > 0 ? (
              visibleScans.map((scan, i) => (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  key={scan.id}
                >
                  <Link href={`/scans/${scan.id}`} className="block group hover:bg-white/[0.02] transition-colors">
                    <div className="p-4 md:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-1">
                          <span className="font-mono text-sm text-primary/80">#{scan.id.toString().padStart(4, '0')}</span>
                          {(scan.isParent || scan.status === 'batch_parent') && (
                            <span className="px-1.5 py-0.5 text-xs bg-purple-500/20 text-purple-400 rounded border border-purple-500/30">
                              BATCH
                            </span>
                          )}
                          <h3 className="font-bold text-foreground truncate group-hover:text-primary transition-colors">
                            {scan.targetUrl}
                          </h3>
                        </div>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span className="flex items-center gap-1.5">
                             <ClockIcon /> 
                             {scan.startTime ? format(new Date(scan.startTime), "PP p") : "Not started"}
                          </span>
                          {scan.status === 'completed' && scan.endTime && (
                            <span className="hidden md:inline text-xs border border-border px-1.5 rounded bg-background/50">
                               Duration: {Math.round((new Date(scan.endTime).getTime() - new Date(scan.startTime!).getTime()) / 1000)}s
                            </span>
                          )}
                          {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (scan as any).completionReason && (
                            <span className={cn(
                              "hidden lg:inline text-xs px-1.5 py-0.5 rounded border",
                              scan.status === 'completed' ? "bg-green-500/10 text-green-500 border-green-500/20" :
                              scan.status === 'failed' ? "bg-red-500/10 text-red-500 border-red-500/20" : 
                              "bg-amber-500/10 text-amber-500 border-amber-500/20"
                            )}>
                               {(scan as any).completionReason.length > 40 
                                 ? (scan as any).completionReason.substring(0, 40) + "..." 
                                 : (scan as any).completionReason}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-6">
                        {/* Summary Mini-Badges */}
                        {scan.summary && (
                          <div className="flex items-center gap-1 text-xs font-mono">
                            {scan.summary.critical > 0 && (
                              <span className="px-1.5 py-0.5 bg-red-500/20 text-red-500 rounded border border-red-500/30" title="Critical">
                                C:{scan.summary.critical}
                              </span>
                            )}
                            {scan.summary.high > 0 && (
                              <span className="px-1.5 py-0.5 bg-orange-500/20 text-orange-500 rounded border border-orange-500/30" title="High">
                                H:{scan.summary.high}
                              </span>
                            )}
                             {scan.summary.medium > 0 && (
                              <span className="hidden sm:inline-block px-1.5 py-0.5 bg-yellow-500/20 text-yellow-500 rounded border border-yellow-500/30" title="Medium">
                                M:{scan.summary.medium}
                              </span>
                            )}
                          </div>
                        )}
                        
                        <div className="flex items-center gap-4 min-w-[140px] justify-end">
                           {scan.status === 'scanning' && (
                             <div className="flex flex-col items-end gap-1 w-24">
                               <span className="text-xs font-mono text-blue-400">{scan.progress}%</span>
                               <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
                                  <div className="h-full bg-blue-500 transition-all duration-300" style={{ width: `${scan.progress}%` }} />
                               </div>
                             </div>
                           )}
                           <StatusBadge status={scan.status as ScanStatus} className="shadow-sm" />
                        </div>
                      </div>
                    </div>
                  </Link>
                </motion.div>
              ))
            ) : (
              <div className="p-12 text-center">
                <div className="w-16 h-16 bg-muted/50 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Search className="w-8 h-8 text-muted-foreground" />
                </div>
                <h3 className="text-lg font-medium text-foreground">No scans found</h3>
                <p className="text-muted-foreground mt-1 max-w-sm mx-auto">
                  Get started by initiating a vulnerability scan on a target URL.
                </p>
                <Link href="/scans/new" className="inline-block mt-4 text-primary hover:underline">
                  Create your first scan &rarr;
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}

function StatCard({ title, value, icon, trend, trendColor }: any) {
  return (
    <div className="bg-card p-6 rounded-xl border border-border shadow-lg relative overflow-hidden group">
      <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity transform group-hover:scale-110 duration-500">
        <div className="scale-150">{icon}</div>
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-medium text-muted-foreground uppercase tracking-wide">{title}</span>
        <span className="text-3xl font-bold font-mono text-foreground">{value}</span>
        <span className={cn("text-xs font-medium flex items-center gap-1 mt-2", trendColor)}>
          {trend}
        </span>
      </div>
    </div>
  );
}

function ClockIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
  )
}
