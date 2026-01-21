import { useState, useEffect } from "react";
import { Layout } from "@/components/Layout";
import { useToast } from "@/hooks/use-toast";
import { 
  Upload, Play, Square, Download, Database, CheckCircle2, XCircle, 
  Loader2, Eye, MoreVertical, ExternalLink 
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useLocation } from "wouter";

interface TargetResult {
  id: number;
  url: string;
  scanId?: number;
  status: "pending" | "scanning" | "vulnerable" | "clean" | "error";
  vulnerabilitiesCount: number;
}

export default function MassScan() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [targets, setTargets] = useState<string>("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<TargetResult[]>([]);
  const [concurrency, setConcurrency] = useState(50);
  const [threads, setThreads] = useState(10);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setTargets(content);
      const count = content.split("\n").filter((l) => l.trim()).length;
      toast({ title: "✅ تم تحميل الملف", description: `${count} موقع` });
    };
    reader.readAsText(file);
  };

  const startScan = async () => {
    const urlList = targets
      .split("\n")
      .map((url) => url.trim())
      .filter((url) => url && url.startsWith("http"));

    if (urlList.length === 0) {
      toast({ title: "خطأ", description: "أدخل روابط صحيحة", variant: "destructive" });
      return;
    }

    // Initialize results
    const initialResults: TargetResult[] = urlList.map((url, index) => ({
      id: index + 1,
      url,
      status: "pending",
      vulnerabilitiesCount: 0,
    }));
    setResults(initialResults);
    setScanning(true);

    try {
      const res = await fetch("/api/mass-scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targets: urlList,
          concurrency,
          threads,
        }),
      });

      if (!res.ok) throw new Error("فشل بدء الفحص");

      toast({
        title: "⚡ بدأ الفحص",
        description: `${urlList.length} موقع | ${concurrency} متزامن | ${threads} threads`,
      });

      // Poll progress
      pollProgress();
    } catch (err: any) {
      toast({ title: "خطأ", description: err.message, variant: "destructive" });
      setScanning(false);
    }
  };

  const pollProgress = () => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch("/api/mass-scan/progress");
        if (!res.ok) throw new Error("Failed to get progress");
        
        const data = await res.json();

        if (data.results && Array.isArray(data.results)) {
          setResults(data.results);
        }

        if (!data.running) {
          clearInterval(interval);
          setScanning(false);
          
          const vulnerable = data.results?.filter((r: any) => r.vulnerabilitiesCount > 0).length || 0;
          toast({
            title: "✅ اكتمل الفحص",
            description: `${vulnerable} موقع مخترق`,
          });
        }
      } catch (err) {
        console.error("Poll error:", err);
      }
    }, 2000);
  };

  const viewScan = (scanId: number) => {
    setLocation(`/scans/${scanId}`);
  };

  const startDump = async (scanId: number) => {
    try {
      // Get first vulnerability from scan
      const vulnsRes = await fetch(`/api/scans/${scanId}/vulnerabilities`);
      const vulns = await vulnsRes.json();
      
      if (vulns.length === 0) {
        toast({ title: "خطأ", description: "لا توجد ثغرات", variant: "destructive" });
        return;
      }

      const res = await fetch(`/api/vulnerabilities/${vulns[0].id}/dump/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      if (!res.ok) throw new Error("فشل بدء الاستخراج");

      toast({
        title: "🗄️ بدأ Dump",
        description: "جارٍ استخراج قاعدة البيانات...",
      });
    } catch (err: any) {
      toast({ title: "خطأ", description: err.message, variant: "destructive" });
    }
  };

  const exportResults = () => {
    const vulnerable = results.filter((r) => r.vulnerabilitiesCount > 0);
    if (vulnerable.length === 0) {
      toast({ title: "لا توجد نتائج", description: "لم يتم العثور على ثغرات" });
      return;
    }

    const csv = [
      "ID,URL,Status,Vulnerabilities,Scan ID",
      ...vulnerable.map(
        (r) => `${r.id},${r.url},${r.status},${r.vulnerabilitiesCount},${r.scanId || ""}`
      ),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mass-scan-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    toast({ title: "✅ تم التصدير", description: `${vulnerable.length} نتيجة` });
  };

  const targetCount = targets.split("\n").filter((l) => l.trim() && l.trim().startsWith("http")).length;
  const stats = {
    total: results.length,
    vulnerable: results.filter((r) => r.vulnerabilitiesCount > 0).length,
    clean: results.filter((r) => r.status === "clean").length,
    scanning: results.filter((r) => r.status === "scanning").length,
  };

  return (
    <Layout>
      <div className="container mx-auto p-6 space-y-6" dir="rtl">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold">Mass Scanner</h1>
            <p className="text-muted-foreground mt-2">استخدام المحرك الأصلي للفحص الشامل</p>
          </div>
          <Button onClick={() => setLocation("/dump")} variant="outline" size="lg">
            <Database className="h-5 w-5 mr-2" />
            صفحة Dump
          </Button>
        </div>

        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle>المواقع المستهدفة</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => document.getElementById("file-upload")?.click()}>
                <Upload className="h-4 w-4 mr-2" />
                رفع ملف
              </Button>
              <input
                id="file-upload"
                type="file"
                accept=".txt"
                className="hidden"
                onChange={handleFileUpload}
              />
              {targetCount > 0 && (
                <Badge variant="secondary" className="text-lg px-4">
                  {targetCount} موقع
                </Badge>
              )}
            </div>

            <Textarea
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder="http://testphp.vulnweb.com/artists.php?artist=1&#10;http://example.com/page.php?id=1"
              className="min-h-[150px] font-mono text-sm"
              disabled={scanning}
            />

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>المواقع المتزامنة</Label>
                <Input
                  type="number"
                  value={concurrency}
                  onChange={(e) => setConcurrency(Number(e.target.value))}
                  min={1}
                  max={200}
                  disabled={scanning}
                />
              </div>
              <div>
                <Label>Threads لكل موقع</Label>
                <Input
                  type="number"
                  value={threads}
                  onChange={(e) => setThreads(Number(e.target.value))}
                  min={1}
                  max={50}
                  disabled={scanning}
                />
              </div>
            </div>

            <div className="flex gap-2">
              {!scanning ? (
                <Button onClick={startScan} disabled={targetCount === 0} size="lg">
                  <Play className="h-5 w-5 mr-2" />
                  بدء الفحص ({targetCount} موقع)
                </Button>
              ) : (
                <Button variant="destructive" size="lg" onClick={() => setScanning(false)}>
                  <Square className="h-5 w-5 mr-2" />
                  إيقاف
                </Button>
              )}
              {stats.vulnerable > 0 && (
                <Button variant="outline" size="lg" onClick={exportResults}>
                  <Download className="h-5 w-5 mr-2" />
                  تصدير
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Success Box */}
        {stats.vulnerable > 0 && (
          <Card className="border-green-500 border-2 bg-green-50 dark:bg-green-950">
            <CardHeader>
              <CardTitle className="text-green-600 flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5" />
                Success - المواقع المخترقة والمؤكدة
                <Badge className="bg-green-600">{stats.vulnerable}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {results
                  .filter((r) => r.vulnerabilitiesCount > 0)
                  .map((result, idx) => (
                    <div
                      key={result.id}
                      className="flex items-center justify-between p-3 bg-white dark:bg-gray-900 rounded-lg"
                    >
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className="w-8 h-8 flex items-center justify-center">
                          {idx + 1}
                        </Badge>
                        <div>
                          <div className="font-medium">{result.url}</div>
                          <div className="text-sm text-muted-foreground">
                            {result.vulnerabilitiesCount} ثغرات - Dump متاح ✅
                          </div>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => setLocation(`/dump?scanId=${result.scanId}`)}>
                              <Database className="h-4 w-4 mr-2" />
                              Dump في الصفحة الأساسية
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => window.open(`/dump?scanId=${result.scanId}`, "_blank")}
                            >
                              <ExternalLink className="h-4 w-4 mr-2" />
                              Dump في نافذة جديدة
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => viewScan(result.scanId!)}>
                              <Eye className="h-4 w-4 mr-2" />
                              عرض تفاصيل الفحص
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </div>
                  ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Stats */}
        {results.length > 0 && (
          <div className="grid grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-6 text-center">
                <div className="text-3xl font-bold">{stats.total}</div>
                <div className="text-sm text-muted-foreground">إجمالي</div>
              </CardContent>
            </Card>
            <Card className="border-blue-500">
              <CardContent className="pt-6 text-center">
                <div className="text-3xl font-bold text-blue-600">{stats.scanning}</div>
                <div className="text-sm text-muted-foreground">جارٍ الفحص</div>
              </CardContent>
            </Card>
            <Card className="border-green-500">
              <CardContent className="pt-6 text-center">
                <div className="text-3xl font-bold text-green-600">{stats.vulnerable}</div>
                <div className="text-sm text-muted-foreground">مخترق ✅</div>
              </CardContent>
            </Card>
            <Card className="border-gray-500">
              <CardContent className="pt-6 text-center">
                <div className="text-3xl font-bold text-gray-600">{stats.clean}</div>
                <div className="text-sm text-muted-foreground">نظيف</div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Results Table */}
        {results.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>النتائج</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-right w-[50px]">#</TableHead>
                    <TableHead className="text-right">الموقع</TableHead>
                    <TableHead className="text-right w-[120px]">الحالة</TableHead>
                    <TableHead className="text-right w-[100px]">الثغرات</TableHead>
                    <TableHead className="text-right w-[200px]">الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {results.map((result) => (
                    <TableRow key={result.id}>
                      <TableCell className="font-mono">{result.id}</TableCell>
                      <TableCell className="font-mono text-sm">{result.url}</TableCell>
                      <TableCell>
                        {result.status === "vulnerable" && (
                          <Badge className="bg-green-500">
                            <CheckCircle2 className="h-3 w-3 mr-1" />
                            مخترق
                          </Badge>
                        )}
                        {result.status === "clean" && (
                          <Badge variant="secondary">
                            <XCircle className="h-3 w-3 mr-1" />
                            نظيف
                          </Badge>
                        )}
                        {result.status === "scanning" && (
                          <Badge variant="default">
                            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                            جارٍ...
                          </Badge>
                        )}
                        {result.status === "pending" && <Badge variant="outline">قيد الانتظار</Badge>}
                      </TableCell>
                      <TableCell className="text-center">
                        {result.vulnerabilitiesCount > 0 ? (
                          <Badge variant="destructive">{result.vulnerabilitiesCount}</Badge>
                        ) : (
                          "-"
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          {result.scanId && (
                            <>
                              <Button size="sm" variant="outline" onClick={() => viewScan(result.scanId!)}>
                                <Eye className="h-4 w-4 mr-1" />
                                عرض
                              </Button>
                              {result.vulnerabilitiesCount > 0 && (
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button size="sm" className="bg-green-600 hover:bg-green-700">
                                      <Database className="h-4 w-4 mr-1" />
                                      Dump
                                      <MoreVertical className="h-3 w-3 ml-1" />
                                    </Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent>
                                    <DropdownMenuItem onClick={() => setLocation(`/dump?scanId=${result.scanId}`)}>
                                      <Database className="h-4 w-4 mr-2" />
                                      Dump في الصفحة الأساسية
                                    </DropdownMenuItem>
                                    <DropdownMenuItem
                                      onClick={() => window.open(`/dump?scanId=${result.scanId}`, "_blank")}
                                    >
                                      <ExternalLink className="h-4 w-4 mr-2" />
                                      Dump في نافذة جديدة
                                    </DropdownMenuItem>
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              )}
                            </>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}
