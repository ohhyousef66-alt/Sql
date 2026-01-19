import { useEffect, useRef } from "react";
import { ScanLog } from "@shared/schema";
import { cn } from "@/lib/utils";
import { format } from "date-fns";
import { Terminal } from "lucide-react";

interface LiveConsoleProps {
  logs: ScanLog[];
  height?: string;
}

export function LiveConsole({ logs, height = "400px" }: LiveConsoleProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="rounded-lg border border-border bg-black/50 overflow-hidden shadow-inner flex flex-col font-mono text-sm">
      <div className="bg-muted/50 px-4 py-2 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Terminal size={14} />
          <span className="text-xs font-bold uppercase tracking-wider">Live Execution Log</span>
        </div>
        <div className="flex gap-1.5">
           <div className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
           <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
           <div className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
        </div>
      </div>
      
      <div className="overflow-y-auto p-4 space-y-1 font-mono text-xs md:text-sm" style={{ height }}>
        {logs.length === 0 && (
          <div className="text-muted-foreground italic opacity-50 text-center py-10">
            Waiting for scan process to initialize...
          </div>
        )}
        
        {logs.map((log) => (
          <div key={log.id} className="flex gap-3 hover:bg-white/5 p-0.5 rounded">
            <span className="text-muted-foreground shrink-0 select-none">
              {log.timestamp ? format(new Date(log.timestamp), "HH:mm:ss.SSS") : "--:--:--"}
            </span>
            <span className={cn(
              "font-bold uppercase w-16 shrink-0",
              log.level === "error" ? "text-red-500" :
              log.level === "warn" ? "text-yellow-500" :
              log.level === "success" ? "text-green-500" : "text-blue-400"
            )}>
              [{log.level}]
            </span>
            <span className={cn(
               "break-all",
               log.level === "error" ? "text-red-400" : "text-gray-300"
            )}>
              {log.message}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
