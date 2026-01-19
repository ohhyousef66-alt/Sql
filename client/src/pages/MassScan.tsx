import { useState, useCallback, useEffect, useMemo } from "react";
import { Layout } from "@/components/Layout";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { 
  Layers, Upload, Play, Square, Download, ChevronRight, 
  FileText, AlertTriangle, CheckCircle, Clock, Target,
  Trash2, Flag, ArrowUpRight, Settings2, RefreshCw, Loader2
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { UploadedFile, StagedTarget, StageRun } from "@shared/schema";

const STAGE_INFO = {
  1: { name: "Discovery", description: "Crawl and discover endpoints", color: "bg-blue-500" },
  2: { name: "Heuristic Probing", description: "Polyglot probes for differential behavior", color: "bg-yellow-500" },
  3: { name: "Boolean/Error Context", description: "Context-aware payload testing", color: "bg-orange-500" },
  4: { name: "Deep Fuzzing", description: "Full payload suite with zeroSpeedMode", color: "bg-red-500" },
  5: { name: "Confirmation", description: "Multi-vector verification", color: "bg-purple-500" },
};

const STORAGE_KEY = "massscan_session";

function loadSessionState(): { fileId: number | null; stage: number; threads: number } {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      return {
        fileId: parsed.fileId ?? null,
        stage: parsed.stage ?? 1,
        threads: parsed.threads ?? 10,
      };
    }
  } catch {}
  return { fileId: null, stage: 1, threads: 10 };
}

function saveSessionState(state: { fileId: number | null; stage: number; threads: number }): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {}
}

export default function MassScan() {
  const savedState = loadSessionState();
  const [selectedFileId, setSelectedFileId] = useState<number | null>(savedState.fileId);
  const [selectedStage, setSelectedStage] = useState<number>(savedState.stage);
  const [threads, setThreads] = useState(savedState.threads);
  const [selectedTargets, setSelectedTargets] = useState<Set<number>>(new Set());
  const { toast } = useToast();
  
  useEffect(() => {
    saveSessionState({ fileId: selectedFileId, stage: selectedStage, threads });
  }, [selectedFileId, selectedStage, threads]);

  const { data: files = [], isLoading: filesLoading } = useQuery<UploadedFile[]>({
    queryKey: ["/api/mass-scan/files"],
  });

  const { data: fileDetails, isRefetching: isRefetchingDetails } = useQuery<{
    file: UploadedFile;
    targets: StagedTarget[];
    stageRuns: StageRun[];
  }>({
    queryKey: ["/api/mass-scan/files", selectedFileId],
    enabled: !!selectedFileId,
    refetchInterval: (query) => {
      const data = query.state.data;
      const hasRunningStage = data?.stageRuns?.some(run => run.status === "running" || run.status === "pending");
      return hasRunningStage ? 2000 : false;
    },
  });

  const hasRunningStage = useMemo(() => {
    return fileDetails?.stageRuns?.some(run => run.status === "running" || run.status === "pending") ?? false;
  }, [fileDetails?.stageRuns]);

  const { data: flaggedTargets = [] } = useQuery<StagedTarget[]>({
    queryKey: ["/api/mass-scan/flagged-targets"],
  });

  const uploadMutation = useMutation({
    mutationFn: async (data: { filename: string; content: string }) => {
      const response = await apiRequest("POST", "/api/mass-scan/upload", data);
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/mass-scan/files"] });
      setSelectedFileId(data.file.id);
      toast({
        title: "File Uploaded",
        description: `${data.validUrls} valid URLs loaded, ${data.invalidUrls} invalid`,
      });
    },
    onError: (err: any) => {
      toast({
        title: "Upload Failed",
        description: err.message || "Failed to upload file",
        variant: "destructive",
      });
    },
  });

  const runStageMutation = useMutation({
    mutationFn: async (data: { fileId: number; stageNumber: number; threads: number }) => {
      const response = await apiRequest("POST", `/api/mass-scan/files/${data.fileId}/run-stage`, {
        stageNumber: data.stageNumber,
        threads: data.threads,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mass-scan/files", selectedFileId] });
      toast({ title: "Stage Started", description: `Stage ${selectedStage} is now running` });
    },
    onError: (err: any) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (fileId: number) => {
      await apiRequest("DELETE", `/api/mass-scan/files/${fileId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mass-scan/files"] });
      setSelectedFileId(null);
      toast({ title: "File Deleted" });
    },
  });

  const promoteMutation = useMutation({
    mutationFn: async (data: { fileId: number; targetIds: number[]; toStage: number }) => {
      const response = await apiRequest("POST", `/api/mass-scan/files/${data.fileId}/promote`, {
        targetIds: data.targetIds,
        toStage: data.toStage,
      });
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/mass-scan/files", selectedFileId] });
      setSelectedTargets(new Set());
      toast({ title: "Targets Promoted", description: `${data.promoted} targets ready for next stage` });
    },
  });

  const stopStageMutation = useMutation({
    mutationFn: async (runId: number) => {
      const response = await apiRequest("POST", `/api/mass-scan/runs/${runId}/stop`, {});
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mass-scan/files", selectedFileId] });
      toast({ title: "Stage Stopped", description: "Stage execution has been stopped" });
    },
    onError: (err: any) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/mass-scan/files", selectedFileId] });
    queryClient.invalidateQueries({ queryKey: ["/api/mass-scan/flagged-targets"] });
  };

  const targetsReadyForStage = useMemo(() => {
    if (!fileDetails?.targets) return 0;
    return fileDetails.targets.filter(t => 
      t.currentStage === selectedStage - 1 && t.status === "pending"
    ).length;
  }, [fileDetails?.targets, selectedStage]);

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      uploadMutation.mutate({ filename: file.name, content });
    };
    reader.readAsText(file);
  }, [uploadMutation]);

  const handleExport = async (fileId: number, flaggedOnly: boolean = false) => {
    const url = `/api/mass-scan/files/${fileId}/export${flaggedOnly ? '?flagged=true' : ''}`;
    window.open(url, '_blank');
  };

  const handlePromoteSelected = () => {
    if (!selectedFileId || selectedTargets.size === 0) return;
    promoteMutation.mutate({
      fileId: selectedFileId,
      targetIds: Array.from(selectedTargets),
      toStage: selectedStage + 1,
    });
  };

  const getStageStatus = (target: StagedTarget) => {
    if (target.isAnomaly) return { icon: Flag, color: "text-yellow-500", label: "Flagged" };
    if (target.status === "completed") return { icon: CheckCircle, color: "text-green-500", label: "Completed" };
    if (target.status === "processing") return { icon: Clock, color: "text-blue-500", label: "Processing" };
    return { icon: Target, color: "text-muted-foreground", label: "Pending" };
  };

  return (
    <Layout>
      <div className="container mx-auto py-8 px-4">
        <div className="mb-8 flex items-center gap-4">
          <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center ring-4 ring-primary/20">
            <Layers className="w-8 h-8 text-primary" />
          </div>
          <div>
            <h1 className="text-3xl font-bold font-display">Mass-Scan Pipeline</h1>
            <p className="text-muted-foreground">
              5-stage pipeline for scanning up to 5,000 targets with intelligent filtering
            </p>
          </div>
        </div>

        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-3">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center justify-between gap-2">
                  <span>Target Files</span>
                  <label className="cursor-pointer">
                    <Button size="sm" variant="outline" asChild>
                      <span>
                        <Upload className="w-4 h-4 mr-1" />
                        Upload
                      </span>
                    </Button>
                    <input
                      type="file"
                      accept=".txt,.csv"
                      onChange={handleFileUpload}
                      className="hidden"
                      data-testid="input-file-upload"
                    />
                  </label>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <ScrollArea className="h-[400px]">
                  {filesLoading ? (
                    <div className="p-4 text-center text-muted-foreground">Loading...</div>
                  ) : files.length === 0 ? (
                    <div className="p-4 text-center text-muted-foreground">
                      No files uploaded yet
                    </div>
                  ) : (
                    <div className="divide-y">
                      {files.map((file) => (
                        <div
                          key={file.id}
                          className={`p-3 cursor-pointer hover-elevate ${
                            selectedFileId === file.id ? "bg-accent" : ""
                          }`}
                          onClick={() => setSelectedFileId(file.id)}
                          data-testid={`file-item-${file.id}`}
                        >
                          <div className="flex items-center gap-2">
                            <FileText className="w-4 h-4 text-muted-foreground" />
                            <span className="font-medium truncate flex-1">{file.filename}</span>
                            <Button
                              size="icon"
                              variant="ghost"
                              className="h-6 w-6"
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteMutation.mutate(file.id);
                              }}
                              data-testid={`button-delete-file-${file.id}`}
                            >
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          </div>
                          <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                            <span>{file.validUrls} URLs</span>
                            <Badge variant="outline" className="text-xs">
                              Stage {file.currentStage || 0}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>

            <Card className="mt-4">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center gap-2">
                  <Flag className="w-4 h-4 text-yellow-500" />
                  Flagged Targets
                </CardTitle>
                <CardDescription>
                  URLs showing anomalies in Stage 2-3
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <ScrollArea className="h-[200px]">
                  {flaggedTargets.length === 0 ? (
                    <div className="p-4 text-center text-muted-foreground text-sm">
                      No flagged targets yet
                    </div>
                  ) : (
                    <div className="divide-y">
                      {flaggedTargets.slice(0, 20).map((target) => (
                        <div key={target.id} className="p-2 text-xs">
                          <div className="truncate font-mono">{target.url}</div>
                          <div className="text-muted-foreground mt-1">
                            {target.anomalyReason || "Deviation detected"}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          <div className="col-span-9">
            {!selectedFileId ? (
              <Card className="h-[600px] flex items-center justify-center">
                <div className="text-center text-muted-foreground">
                  <Layers className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>Select a file or upload a new target list to begin</p>
                </div>
              </Card>
            ) : (
              <Tabs defaultValue="pipeline">
                <TabsList className="mb-4">
                  <TabsTrigger value="pipeline" data-testid="tab-pipeline">Pipeline Stages</TabsTrigger>
                  <TabsTrigger value="targets" data-testid="tab-targets">Targets ({fileDetails?.targets.length || 0})</TabsTrigger>
                  <TabsTrigger value="runs" data-testid="tab-runs">Stage Runs</TabsTrigger>
                </TabsList>

                <TabsContent value="pipeline">
                  <Card>
                    <CardHeader>
                      <CardTitle>Stage Selector</CardTitle>
                      <CardDescription>
                        Select a stage to run against your targets. Stages 4-5 use zeroSpeedMode for maximum detection quality.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-5 gap-4 mb-6">
                        {[1, 2, 3, 4, 5].map((stage) => {
                          const info = STAGE_INFO[stage as keyof typeof STAGE_INFO];
                          const isSelected = selectedStage === stage;
                          const currentStage = fileDetails?.file.currentStage || 0;
                          const isCompleted = currentStage >= stage;
                          
                          return (
                            <div
                              key={stage}
                              className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                                isSelected 
                                  ? "border-primary bg-primary/5" 
                                  : isCompleted 
                                    ? "border-green-500/50 bg-green-500/5"
                                    : "border-border hover:border-primary/50"
                              }`}
                              onClick={() => setSelectedStage(stage)}
                              data-testid={`stage-selector-${stage}`}
                            >
                              <div className="flex items-center gap-2 mb-2">
                                <div className={`w-6 h-6 rounded-full ${info.color} flex items-center justify-center text-white text-xs font-bold`}>
                                  {stage}
                                </div>
                                {isCompleted && <CheckCircle className="w-4 h-4 text-green-500" />}
                              </div>
                              <div className="font-medium text-sm">{info.name}</div>
                              <div className="text-xs text-muted-foreground mt-1">{info.description}</div>
                              {stage >= 4 && (
                                <Badge variant="secondary" className="mt-2 text-xs">
                                  ZeroSpeed
                                </Badge>
                              )}
                            </div>
                          );
                        })}
                      </div>

                      <div className="border-t pt-6">
                        <div className="flex items-center gap-6 mb-6">
                          <div className="flex-1">
                            <label className="text-sm font-medium mb-2 block">Threads: {threads}</label>
                            <Slider
                              value={[threads]}
                              onValueChange={(v) => setThreads(v[0])}
                              min={1}
                              max={100}
                              step={1}
                              data-testid="slider-threads"
                            />
                          </div>
                          <div className="text-right">
                            <div className="text-sm text-muted-foreground mb-1 flex items-center gap-2 justify-end">
                              <span className="font-medium text-foreground">{targetsReadyForStage}</span> targets ready
                              {hasRunningStage && (
                                <Badge variant="secondary" className="ml-2">
                                  <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                                  Running
                                </Badge>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="flex gap-4 flex-wrap">
                          <Button
                            size="lg"
                            onClick={() => selectedFileId && runStageMutation.mutate({
                              fileId: selectedFileId,
                              stageNumber: selectedStage,
                              threads,
                            })}
                            disabled={runStageMutation.isPending || hasRunningStage || targetsReadyForStage === 0}
                            data-testid="button-run-stage"
                          >
                            {runStageMutation.isPending ? (
                              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                            ) : (
                              <Play className="w-4 h-4 mr-2" />
                            )}
                            Run Stage {selectedStage}
                          </Button>
                          <Button
                            variant="outline"
                            size="lg"
                            onClick={handleRefresh}
                            disabled={isRefetchingDetails}
                            data-testid="button-refresh"
                          >
                            <RefreshCw className={`w-4 h-4 mr-2 ${isRefetchingDetails ? 'animate-spin' : ''}`} />
                            Refresh
                          </Button>
                          <Button
                            variant="outline"
                            size="lg"
                            onClick={() => selectedFileId && handleExport(selectedFileId)}
                            data-testid="button-export-all"
                          >
                            <Download className="w-4 h-4 mr-2" />
                            Export All
                          </Button>
                          <Button
                            variant="outline"
                            size="lg"
                            onClick={() => selectedFileId && handleExport(selectedFileId, true)}
                            data-testid="button-export-flagged"
                          >
                            <Flag className="w-4 h-4 mr-2" />
                            Export Flagged
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="targets">
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <CardTitle>Target URLs</CardTitle>
                          <CardDescription>
                            Select targets to promote to the next stage
                          </CardDescription>
                        </div>
                        {selectedTargets.size > 0 && (
                          <Button onClick={handlePromoteSelected} data-testid="button-promote-selected">
                            <ArrowUpRight className="w-4 h-4 mr-2" />
                            Promote {selectedTargets.size} to Stage {selectedStage + 1}
                          </Button>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="p-0">
                      <ScrollArea className="h-[500px]">
                        <table className="w-full">
                          <thead className="sticky top-0 bg-card border-b">
                            <tr className="text-left text-xs text-muted-foreground">
                              <th className="p-3 w-8">
                                <input
                                  type="checkbox"
                                  onChange={(e) => {
                                    if (e.target.checked) {
                                      setSelectedTargets(new Set(fileDetails?.targets.map(t => t.id) || []));
                                    } else {
                                      setSelectedTargets(new Set());
                                    }
                                  }}
                                  data-testid="checkbox-select-all"
                                />
                              </th>
                              <th className="p-3">URL</th>
                              <th className="p-3 w-24">Stage</th>
                              <th className="p-3 w-24">Status</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y">
                            {fileDetails?.targets.map((target) => {
                              const status = getStageStatus(target);
                              const StatusIcon = status.icon;
                              return (
                                <tr key={target.id} className="hover:bg-accent/50">
                                  <td className="p-3">
                                    <input
                                      type="checkbox"
                                      checked={selectedTargets.has(target.id)}
                                      onChange={(e) => {
                                        const newSet = new Set(selectedTargets);
                                        if (e.target.checked) {
                                          newSet.add(target.id);
                                        } else {
                                          newSet.delete(target.id);
                                        }
                                        setSelectedTargets(newSet);
                                      }}
                                      data-testid={`checkbox-target-${target.id}`}
                                    />
                                  </td>
                                  <td className="p-3 font-mono text-sm truncate max-w-md">
                                    {target.url}
                                  </td>
                                  <td className="p-3">
                                    <Badge variant="outline">{target.currentStage}</Badge>
                                  </td>
                                  <td className="p-3">
                                    <div className="flex items-center gap-1">
                                      <StatusIcon className={`w-4 h-4 ${status.color}`} />
                                      <span className="text-xs">{status.label}</span>
                                    </div>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="runs">
                  <Card>
                    <CardHeader>
                      <CardTitle>Stage Execution History</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {!fileDetails?.stageRuns.length ? (
                        <div className="text-center text-muted-foreground py-8">
                          No stage runs yet
                        </div>
                      ) : (
                        <div className="space-y-4">
                          {fileDetails.stageRuns.map((run) => {
                            const stageInfo = STAGE_INFO[run.stageNumber as keyof typeof STAGE_INFO];
                            const progress = run.totalTargets > 0 
                              ? Math.round((run.processedTargets / run.totalTargets) * 100) 
                              : 0;
                            
                            return (
                              <div key={run.id} className="border rounded-lg p-4">
                                <div className="flex items-center justify-between mb-3">
                                  <div className="flex items-center gap-3">
                                    <div className={`w-8 h-8 rounded-full ${stageInfo.color} flex items-center justify-center text-white font-bold`}>
                                      {run.stageNumber}
                                    </div>
                                    <div>
                                      <div className="font-medium">{stageInfo.name}</div>
                                      <div className="text-xs text-muted-foreground">
                                        {run.totalTargets} targets • {run.threads} threads
                                        {run.zeroSpeedMode && " • ZeroSpeed"}
                                      </div>
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    {(run.status === "running" || run.status === "pending") && (
                                      <Button
                                        size="sm"
                                        variant="destructive"
                                        onClick={() => stopStageMutation.mutate(run.id)}
                                        disabled={stopStageMutation.isPending}
                                        data-testid={`button-stop-run-${run.id}`}
                                      >
                                        <Square className="w-3 h-3 mr-1" />
                                        Stop
                                      </Button>
                                    )}
                                    <Badge variant={
                                      run.status === "completed" ? "default" :
                                      run.status === "running" ? "secondary" :
                                      run.status === "stopped" ? "outline" : "destructive"
                                    }>
                                      {run.status === "running" && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
                                      {run.status}
                                    </Badge>
                                  </div>
                                </div>
                                <Progress value={progress} className="h-2 mb-2" />
                                <div className="flex justify-between text-xs text-muted-foreground">
                                  <span>{run.processedTargets} / {run.totalTargets} processed ({progress}%)</span>
                                  <span>{run.flaggedTargets} flagged • {run.confirmedVulns} confirmed</span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
