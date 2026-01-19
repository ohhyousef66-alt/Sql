import { useState } from "react";
import { useLocation } from "wouter";
import { Layout } from "@/components/Layout";
import { useToast } from "@/hooks/use-toast";
import { Shield, Globe, ArrowRight, Terminal, Cpu, List, Upload, X } from "lucide-react";
import { z } from "zod";
import { Slider } from "@/components/ui/slider";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { apiRequest } from "@/lib/queryClient";
import { useMutation } from "@tanstack/react-query";

const urlSchema = z.string().url();

export default function BatchScan() {
  const [urlsText, setUrlsText] = useState("");
  const [threads, setThreads] = useState(10);
  const [errors, setErrors] = useState<string[]>([]);
  const [, setLocation] = useLocation();
  const { toast } = useToast();

  const batchMutation = useMutation({
    mutationFn: async (data: { targetUrls: string[]; scanMode: string; threads: number }) => {
      const response = await apiRequest("POST", "/api/scans/batch", data);
      return response.json();
    },
  });

  const parseUrls = (text: string): string[] => {
    return text
      .split(/[\n,]/)
      .map(url => url.trim())
      .filter(url => url.length > 0);
  };

  const validUrls = parseUrls(urlsText).filter(url => urlSchema.safeParse(url).success);
  const invalidUrls = parseUrls(urlsText).filter(url => !urlSchema.safeParse(url).success);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrors([]);

    const urls = parseUrls(urlsText);
    
    if (urls.length === 0) {
      setErrors(["Please enter at least one URL"]);
      return;
    }

    if (urls.length > 50) {
      setErrors(["Maximum 50 URLs allowed per batch"]);
      return;
    }

    const invalidList = urls.filter(url => !urlSchema.safeParse(url).success);
    if (invalidList.length > 0) {
      setErrors(invalidList.map(url => `Invalid URL: ${url}`));
      return;
    }

    batchMutation.mutate(
      { targetUrls: urls, scanMode: "sqli", threads },
      {
        onSuccess: (data) => {
          toast({
            title: "Batch Scan Initiated",
            description: `${urls.length} targets queued for scanning.`,
            variant: "default",
          });
          setLocation(`/scans/${data.parentScanId}`);
        },
        onError: (err: any) => {
          toast({
            title: "Error",
            description: err.message || "Failed to start batch scan",
            variant: "destructive",
          });
        },
      }
    );
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setUrlsText(content);
    };
    reader.readAsText(file);
  };

  return (
    <Layout>
      <div className="max-w-2xl mx-auto mt-12">
        <div className="mb-8 text-center space-y-4">
          <div className="w-20 h-20 bg-primary/10 rounded-full flex items-center justify-center mx-auto ring-4 ring-primary/20 shadow-[0_0_40px_-10px_hsl(var(--primary)/0.5)]">
            <List className="w-10 h-10 text-primary" />
          </div>
          <h1 className="text-3xl font-bold font-display tracking-tight">Batch SQL Injection Scanner</h1>
          <p className="text-muted-foreground max-w-md mx-auto">
            Scan multiple URLs at once. Enter one URL per line or upload a text file with your target list.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="relative">
          <div className="bg-card border border-border p-8 rounded-2xl shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-50" />
             
            <div className="space-y-6">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-medium ml-1 text-foreground/80">
                    Target URLs (one per line)
                  </label>
                  <label className="cursor-pointer text-xs text-primary hover:underline flex items-center gap-1">
                    <Upload className="w-3 h-3" />
                    Upload File
                    <input
                      type="file"
                      accept=".txt,.csv"
                      onChange={handleFileUpload}
                      className="hidden"
                      data-testid="input-file-upload"
                    />
                  </label>
                </div>
                <Textarea
                  value={urlsText}
                  onChange={(e) => setUrlsText(e.target.value)}
                  className="min-h-[200px] font-mono text-sm resize-none"
                  placeholder={`https://example.com
https://test.example.com/page?id=1
https://api.example.com/users`}
                  data-testid="textarea-urls"
                />
                
                <div className="flex items-center justify-between mt-2 text-xs">
                  <span className="text-muted-foreground">
                    {validUrls.length} valid URL{validUrls.length !== 1 ? 's' : ''} 
                    {invalidUrls.length > 0 && (
                      <span className="text-red-500 ml-2">
                        ({invalidUrls.length} invalid)
                      </span>
                    )}
                  </span>
                  <span className="text-muted-foreground">
                    Max: 50 URLs
                  </span>
                </div>

                {errors.length > 0 && (
                  <div className="mt-3 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                    {errors.slice(0, 5).map((err, i) => (
                      <p key={i} className="text-sm text-red-500">{err}</p>
                    ))}
                    {errors.length > 5 && (
                      <p className="text-sm text-red-500">...and {errors.length - 5} more errors</p>
                    )}
                  </div>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 ml-1 text-foreground/80">
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4" />
                    <span>Threads per scan: {threads}</span>
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

              <div className="bg-muted/30 rounded-lg p-4 text-xs font-mono text-muted-foreground border border-border/50">
                <div className="flex items-center gap-2 mb-2 text-foreground/70 font-bold">
                  <Terminal size={14} /> 
                  <span>Batch Scan Features:</span>
                </div>
                <ul className="grid grid-cols-2 gap-2">
                  <li className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                    Parallel Execution
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                    Progress Tracking
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                    Consolidated Reports
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                    Independent Results
                  </li>
                </ul>
              </div>

              <Button 
                type="submit" 
                className="w-full py-6 text-lg font-bold rounded-xl"
                disabled={batchMutation.isPending || validUrls.length === 0}
                data-testid="button-start-batch-scan"
              >
                {batchMutation.isPending ? (
                  <span className="flex items-center gap-2">
                    <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Initiating Batch Scan...
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    Start Batch Scan ({validUrls.length} URLs)
                    <ArrowRight className="w-5 h-5" />
                  </span>
                )}
              </Button>
            </div>
          </div>
        </form>
      </div>
    </Layout>
  );
}
