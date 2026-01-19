import { useState } from "react";
import { useLocation } from "wouter";
import { useCreateScan } from "@/hooks/use-scans";
import { Layout } from "@/components/Layout";
import { useToast } from "@/hooks/use-toast";
import { Shield, Globe, ArrowRight, Terminal, Cpu, Zap, Code } from "lucide-react";
import { z } from "zod";
import { Slider } from "@/components/ui/slider";
import { apiRequest } from "@/lib/queryClient";

const urlSchema = z.string().url("Please enter a valid URL (e.g., https://example.com)");

export default function NewScan() {
  const [url, setUrl] = useState("");
  const [threads, setThreads] = useState(10);
  const [error, setError] = useState<string | null>(null);
  const [engine, setEngine] = useState<"nodejs" | "python">("nodejs");
  const [, setLocation] = useLocation();
  const { mutate, isPending } = useCreateScan();
  const { toast } = useToast();
  const [pythonLoading, setPythonLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const result = urlSchema.safeParse(url);
    if (!result.success) {
      setError(result.error.errors[0].message);
      return;
    }

    if (engine === "python") {
      setPythonLoading(true);
      try {
        const response = await apiRequest("POST", "/api/python-scan", {
          targetUrl: url,
          threads,
        });
        const data = await response.json();
        toast({
          title: "Python Scan Initiated",
          description: `Target ${url} is being analyzed with Python engine.`,
          variant: "default",
        });
        setLocation(`/scans/${data.scanId}`);
      } catch (err: any) {
        toast({
          title: "Error",
          description: err.message || "Failed to start Python scan",
          variant: "destructive",
        });
      } finally {
        setPythonLoading(false);
      }
    } else {
      mutate(
        { targetUrl: url, scanMode: "sqli", threads },
        {
          onSuccess: (data) => {
            toast({
              title: "Scan Initiated",
              description: `Target ${url} is now being analyzed.`,
              variant: "default",
            });
            setLocation(`/scans/${data.id}`);
          },
          onError: (err) => {
            toast({
              title: "Error",
              description: err.message,
              variant: "destructive",
            });
          },
        }
      );
    }
  };

  return (
    <Layout>
      <div className="max-w-2xl mx-auto mt-12">
        <div className="mb-8 text-center space-y-4">
          <div className="w-20 h-20 bg-primary/10 rounded-full flex items-center justify-center mx-auto ring-4 ring-primary/20 shadow-[0_0_40px_-10px_hsl(var(--primary)/0.5)]">
            <Shield className="w-10 h-10 text-primary" />
          </div>
          <h1 className="text-3xl font-bold font-display tracking-tight">SQL Injection Scanner</h1>
          <p className="text-muted-foreground max-w-md mx-auto">
            Enter the target URL to begin SQL injection vulnerability scanning. The engine tests for Blind, Union, Error-based, and Time-based SQLi.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="relative">
          <div className="bg-card border border-border p-8 rounded-2xl shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-50" />
             
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium mb-2 ml-1 text-foreground/80">Target URL</label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Globe className="h-5 w-5 text-muted-foreground group-focus-within:text-primary transition-colors" />
                  </div>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className={`
                      w-full pl-11 pr-4 py-4 rounded-xl bg-background border-2 
                      text-lg font-mono placeholder:text-muted-foreground/50
                      focus:outline-none focus:ring-4 focus:ring-primary/10 transition-all
                      ${error ? "border-red-500 focus:border-red-500" : "border-border focus:border-primary"}
                    `}
                    placeholder="https://example.com"
                    autoFocus
                    data-testid="input-target-url"
                  />
                </div>
                {error && <p className="mt-2 text-sm text-red-500 font-medium ml-1">{error}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 ml-1 text-foreground/80">
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4" />
                    <span>Threads: {threads}</span>
                  </div>
                </label>
                <div className="px-2">
                  <Slider
                    value={[threads]}
                    onValueChange={(value) => setThreads(value[0])}
                    min={1}
                    max={50}
                    step={1}
                    className="w-full"
                    data-testid="slider-threads"
                  />
                  <div className="flex justify-between text-xs text-muted-foreground mt-1">
                    <span>1 (Slow)</span>
                    <span>25 (Balanced)</span>
                    <span>50 (Fast)</span>
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 ml-1 text-foreground/80">
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4" />
                    <span>Scanner Engine</span>
                  </div>
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setEngine("nodejs")}
                    className={`p-4 rounded-xl border-2 transition-all ${
                      engine === "nodejs"
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border hover:border-primary/50 text-muted-foreground"
                    }`}
                    data-testid="button-engine-nodejs"
                  >
                    <Code className="h-5 w-5 mx-auto mb-2" />
                    <div className="text-sm font-medium">Node.js Engine</div>
                    <div className="text-xs opacity-70 mt-1">Full-featured, Real-time</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setEngine("python")}
                    className={`p-4 rounded-xl border-2 transition-all ${
                      engine === "python"
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border hover:border-primary/50 text-muted-foreground"
                    }`}
                    data-testid="button-engine-python"
                  >
                    <Terminal className="h-5 w-5 mx-auto mb-2" />
                    <div className="text-sm font-medium">Python Engine</div>
                    <div className="text-xs opacity-70 mt-1">Reliable, Zero FP</div>
                  </button>
                </div>
              </div>

              <div className="bg-muted/30 rounded-lg p-4 text-xs font-mono text-muted-foreground border border-border/50">
                <div className="flex items-center gap-2 mb-2 text-foreground/70 font-bold">
                  <Terminal size={14} /> 
                  <span>SQL Injection Detection Modules:</span>
                </div>
                <ul className="grid grid-cols-2 gap-2">
                  <li className="flex items-center gap-1.5">
                    <span className="text-green-500">+</span> Error-based SQLi
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="text-green-500">+</span> Union-based SQLi
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="text-green-500">+</span> Boolean-blind SQLi
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="text-green-500">+</span> Time-based SQLi
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="text-green-500">+</span> Stacked Queries
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="text-green-500">+</span> Second-Order SQLi
                  </li>
                </ul>
              </div>

              <button
                type="submit"
                disabled={isPending || pythonLoading}
                className="
                  w-full py-4 rounded-xl font-bold text-lg flex items-center justify-center gap-2
                  bg-primary text-primary-foreground 
                  shadow-[0_0_20px_-5px_hsl(var(--primary)/0.6)]
                  hover:shadow-[0_0_30px_-5px_hsl(var(--primary)/0.8)] hover:-translate-y-0.5
                  active:translate-y-0 active:scale-[0.99]
                  disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none
                  transition-all duration-200
                "
                data-testid="button-start-scan"
              >
                {(isPending || pythonLoading) ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    {pythonLoading ? "Starting Python Scanner..." : "Initializing..."}
                  </>
                ) : (
                  <>
                    Start {engine === "python" ? "Python" : "Node.js"} SQLi Scan <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
        
        <p className="text-center text-xs text-muted-foreground mt-8">
          By starting a scan, you confirm you have authorization to test this target.
        </p>
      </div>
    </Layout>
  );
}
