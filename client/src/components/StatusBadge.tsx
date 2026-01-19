import { cn } from "@/lib/utils";
import { Loader2, CheckCircle, XCircle, Clock } from "lucide-react";

export type ScanStatus = "pending" | "scanning" | "completed" | "failed";

interface StatusBadgeProps {
  status: ScanStatus;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const styles = {
    pending: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    scanning: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    completed: "bg-green-500/10 text-green-500 border-green-500/20",
    failed: "bg-red-500/10 text-red-500 border-red-500/20",
  };

  const icons = {
    pending: <Clock className="w-3.5 h-3.5" />,
    scanning: <Loader2 className="w-3.5 h-3.5 animate-spin" />,
    completed: <CheckCircle className="w-3.5 h-3.5" />,
    failed: <XCircle className="w-3.5 h-3.5" />,
  };

  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border uppercase tracking-wider",
      styles[status],
      className
    )}>
      {icons[status]}
      {status}
    </span>
  );
}
