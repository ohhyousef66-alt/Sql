import { Link, useLocation } from "wouter";
import { ShieldAlert, LogOut, Terminal, LayoutDashboard, Layers } from "lucide-react";
import { cn } from "@/lib/utils";

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();

  const navItems = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scans/new", label: "New Scan", icon: ShieldAlert },
    { href: "/scans/mass", label: "Mass Scan", icon: Layers },
  ];

  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-background text-foreground">
      {/* Sidebar */}
      <aside className="w-full md:w-64 border-r border-border bg-card/50 backdrop-blur-sm md:h-screen flex-shrink-0 sticky top-0">
        <div className="p-6 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-primary/20 flex items-center justify-center text-primary border border-primary/50">
              <ShieldAlert size={24} />
            </div>
            <h1 className="text-xl font-bold tracking-tight font-display">SecScan<span className="text-primary">.io</span></h1>
          </div>
        </div>

        <nav className="p-4 space-y-1">
          {navItems.map((item) => {
            const isActive = location === item.href;
            return (
              <Link key={item.href} href={item.href} className={cn(
                "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group font-medium",
                isActive 
                  ? "bg-primary/10 text-primary border border-primary/20 shadow-[0_0_15px_-3px_hsl(var(--primary)/0.3)]" 
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )}>
                <item.icon className={cn("w-5 h-5", isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <header className="h-16 border-b border-border bg-background/50 backdrop-blur supports-[backdrop-filter]:bg-background/20 sticky top-0 z-20 px-6 flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
             <Terminal className="w-4 h-4" />
             <span className="font-mono">system_ready</span>
             <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse ml-2" />
          </div>
          <div className="font-mono text-xs text-primary/70 border border-primary/20 px-2 py-1 rounded bg-primary/5">
             v1.0.0-stable
          </div>
        </header>
        <div className="p-6 md:p-8 max-w-7xl mx-auto animate-in fade-in duration-500">
          {children}
        </div>
      </main>
    </div>
  );
}
