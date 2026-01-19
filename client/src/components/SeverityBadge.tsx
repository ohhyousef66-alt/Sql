import { cn } from "@/lib/utils";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info" | "Informational";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  // Normalize casing
  let normalized = (severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()) as Severity;
  
  // Map "Informational" to its own category
  if (normalized === "Informational") {
    normalized = "Informational";
  }

  const styles: Record<string, string> = {
    Critical: "bg-red-500/10 text-red-500 border-red-500/50 shadow-[0_0_10px_-3px_rgba(239,68,68,0.4)]",
    High: "bg-orange-500/10 text-orange-500 border-orange-500/50",
    Medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/50",
    Low: "bg-blue-500/10 text-blue-500 border-blue-500/50",
    Info: "bg-gray-500/10 text-gray-400 border-gray-500/50",
    Informational: "bg-sky-500/10 text-sky-500 border-sky-500/50",
  };

  return (
    <span className={cn(
      "inline-flex items-center justify-center px-2.5 py-0.5 rounded text-xs font-bold border font-mono",
      styles[normalized] || styles.Info,
      className
    )}>
      {normalized.toUpperCase()}
    </span>
  );
}
