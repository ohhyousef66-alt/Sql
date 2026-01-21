import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Loader2, Database, Table2, ChevronRight, Download, Play, X } from "lucide-react";
import { useState, useEffect } from "react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";

interface ExtractedDatabase {
  id: number;
  databaseName: string;
  dbType: string;
  extractionMethod: string;
  tableCount: number;
  status: string;
  metadata?: {
    version?: string;
    user?: string;
    currentDb?: string;
  };
}

interface ExtractedTable {
  id: number;
  tableName: string;
  rowCount: number;
  columnCount: number;
  status: string;
}

interface ExtractedColumn {
  id: number;
  columnName: string;
  dataType: string;
  isNullable: boolean;
  columnKey: string;
}

interface ExtractedDataRow {
  id: number;
  rowIndex: number;
  rowData: Record<string, any>;
}

interface DumpingJob {
  id: number;
  targetType: string;
  status: string;
  progress: number;
  itemsTotal: number;
  itemsExtracted: number;
}

interface DataExplorerProps {
  vulnerabilityId: number;
  targetUrl: string;
}

export default function DataExplorer({ vulnerabilityId, targetUrl }: DataExplorerProps) {
  const { toast } = useToast();
  const [databases, setDatabases] = useState<ExtractedDatabase[]>([]);
  const [selectedDb, setSelectedDb] = useState<number | null>(null);
  const [tables, setTables] = useState<ExtractedTable[]>([]);
  const [selectedTable, setSelectedTable] = useState<number | null>(null);
  const [columns, setColumns] = useState<ExtractedColumn[]>([]);
  const [data, setData] = useState<ExtractedDataRow[]>([]);
  const [jobs, setJobs] = useState<DumpingJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [dumpingInProgress, setDumpingInProgress] = useState(false);

  useEffect(() => {
    loadDatabases();
    loadJobs();
    const interval = setInterval(loadJobs, 3000); // Poll jobs every 3 seconds
    return () => clearInterval(interval);
  }, [vulnerabilityId]);

  useEffect(() => {
    if (selectedDb) {
      loadTables(selectedDb);
    }
  }, [selectedDb]);

  useEffect(() => {
    if (selectedTable) {
      loadColumns(selectedTable);
      loadData(selectedTable);
    }
  }, [selectedTable]);

  const loadDatabases = async () => {
    try {
      const res = await fetch(`/api/vulnerabilities/${vulnerabilityId}/databases`);
      if (res.ok) {
        const dbs = await res.json();
        setDatabases(dbs);
      }
    } catch (error) {
      console.error("Failed to load databases:", error);
    }
  };

  const loadTables = async (dbId: number) => {
    try {
      setLoading(true);
      const res = await fetch(`/api/databases/${dbId}/tables`);
      if (res.ok) {
        const tbls = await res.json();
        setTables(tbls);
      }
    } catch (error) {
      console.error("Failed to load tables:", error);
    } finally {
      setLoading(false);
    }
  };

  const loadColumns = async (tableId: number) => {
    try {
      const res = await fetch(`/api/tables/${tableId}/columns`);
      if (res.ok) {
        const cols = await res.json();
        setColumns(cols);
      }
    } catch (error) {
      console.error("Failed to load columns:", error);
    }
  };

  const loadData = async (tableId: number, limit = 100, offset = 0) => {
    try {
      setLoading(true);
      const res = await fetch(`/api/tables/${tableId}/data?limit=${limit}&offset=${offset}`);
      if (res.ok) {
        const result = await res.json();
        setData(result.data);
      }
    } catch (error) {
      console.error("Failed to load data:", error);
    } finally {
      setLoading(false);
    }
  };

  const loadJobs = async () => {
    try {
      const res = await fetch(`/api/vulnerabilities/${vulnerabilityId}/jobs`);
      if (res.ok) {
        const j = await res.json();
        setJobs(j);
        const inProgress = j.some((job: DumpingJob) => job.status === "running" || job.status === "pending");
        setDumpingInProgress(inProgress);
      }
    } catch (error) {
      console.error("Failed to load jobs:", error);
    }
  };

  const startDatabaseDump = async () => {
    try {
      setDumpingInProgress(true);
      const res = await fetch(`/api/vulnerabilities/${vulnerabilityId}/dump/start`, {
        method: "POST",
      });
      
      if (res.ok) {
        toast({
          title: "Database dump started",
          description: "Enumerating databases...",
        });
        setTimeout(() => {
          loadDatabases();
          loadJobs();
        }, 2000);
      } else {
        toast({
          title: "Failed to start dump",
          variant: "destructive",
        });
        setDumpingInProgress(false);
      }
    } catch (error) {
      toast({
        title: "Error starting dump",
        variant: "destructive",
      });
      setDumpingInProgress(false);
    }
  };

  const dumpTables = async (dbId: number) => {
    try {
      const res = await fetch(`/api/databases/${dbId}/dump-tables`, {
        method: "POST",
      });
      
      if (res.ok) {
        toast({
          title: "Table dump started",
          description: "Enumerating tables...",
        });
        setTimeout(() => loadTables(dbId), 2000);
      } else {
        toast({
          title: "Failed to dump tables",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Error dumping tables",
        variant: "destructive",
      });
    }
  };

  const dumpColumns = async (tableId: number) => {
    try {
      const res = await fetch(`/api/tables/${tableId}/dump-columns`, {
        method: "POST",
      });
      
      if (res.ok) {
        toast({
          title: "Column dump started",
          description: "Enumerating columns...",
        });
        setTimeout(() => loadColumns(tableId), 2000);
      } else {
        toast({
          title: "Failed to dump columns",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Error dumping columns",
        variant: "destructive",
      });
    }
  };

  const dumpData = async (tableId: number) => {
    try {
      const res = await fetch(`/api/tables/${tableId}/dump-data`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit: 100 }),
      });
      
      if (res.ok) {
        toast({
          title: "Data dump started",
          description: "Extracting table data...",
        });
        setTimeout(() => loadData(tableId), 2000);
      } else {
        toast({
          title: "Failed to dump data",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Error dumping data",
        variant: "destructive",
      });
    }
  };

  const exportToCSV = () => {
    if (data.length === 0 || columns.length === 0) return;
    
    const headers = columns.map(c => c.columnName).join(",");
    const rows = data.map(row => 
      columns.map(c => JSON.stringify(row.rowData[c.columnName] || "")).join(",")
    ).join("\n");
    
    const csv = `${headers}\n${rows}`;
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `table_${selectedTable}_data.csv`;
    a.click();
    URL.revokeObjectURL(url);
    
    toast({
      title: "Exported to CSV",
      description: `${data.length} rows exported`,
    });
  };

  const runningJobs = jobs.filter(j => j.status === "running" || j.status === "pending");

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="p-6 bg-gradient-to-r from-purple-900/20 to-blue-900/20 border-purple-500/30">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              <Database className="w-6 h-6" />
              Data Explorer (SQLi Dumper)
            </h2>
            <p className="text-gray-400 text-sm mt-1">
              Extract and browse database contents
            </p>
          </div>
          <Button
            onClick={startDatabaseDump}
            disabled={dumpingInProgress || databases.length > 0}
            className="bg-gradient-to-r from-purple-500 to-blue-500 hover:from-purple-600 hover:to-blue-600"
          >
            {dumpingInProgress ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Dumping...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 mr-2" />
                Start Database Dump
              </>
            )}
          </Button>
        </div>
      </Card>

      {/* Active Jobs */}
      {runningJobs.length > 0 && (
        <Card className="p-4 border-blue-500/30">
          <h3 className="text-lg font-semibold text-white mb-3">Active Jobs</h3>
          <div className="space-y-2">
            {runningJobs.map(job => (
              <div key={job.id} className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg">
                <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                <div className="flex-1">
                  <div className="text-sm text-white">
                    {job.targetType} extraction
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <div className="h-2 flex-1 bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-purple-500 to-blue-500 transition-all"
                        style={{ width: `${job.progress}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400">{job.progress}%</span>
                  </div>
                </div>
                <span className="text-xs text-gray-400">
                  {job.itemsExtracted}/{job.itemsTotal}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Databases List */}
      {databases.length > 0 && (
        <Card className="p-6 border-purple-500/30">
          <h3 className="text-xl font-bold text-white mb-4">Databases ({databases.length})</h3>
          <Accordion type="single" collapsible className="space-y-2">
            {databases.map((db) => (
              <AccordionItem key={db.id} value={`db-${db.id}`} className="border-gray-700">
                <AccordionTrigger
                  onClick={() => setSelectedDb(db.id)}
                  className="hover:bg-gray-800/50 px-4 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <Database className="w-5 h-5 text-purple-400" />
                    <div className="text-left">
                      <div className="font-semibold text-white">{db.databaseName}</div>
                      <div className="text-xs text-gray-400">
                        {db.dbType} • {db.extractionMethod} • {db.tableCount} tables
                      </div>
                    </div>
                    <Badge variant="outline" className="ml-auto">
                      {db.status}
                    </Badge>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="px-4 pt-2">
                  {db.metadata && (
                    <div className="grid grid-cols-2 gap-2 mb-4 text-sm">
                      {db.metadata.version && (
                        <div>
                          <span className="text-gray-400">Version:</span>{" "}
                          <span className="text-white">{db.metadata.version}</span>
                        </div>
                      )}
                      {db.metadata.user && (
                        <div>
                          <span className="text-gray-400">User:</span>{" "}
                          <span className="text-white">{db.metadata.user}</span>
                        </div>
                      )}
                    </div>
                  )}
                  
                  {selectedDb === db.id && (
                    <>
                      {tables.length === 0 && !loading && (
                        <Button
                          onClick={() => dumpTables(db.id)}
                          size="sm"
                          variant="outline"
                          className="mb-4"
                        >
                          <Play className="w-4 h-4 mr-2" />
                          Dump Tables
                        </Button>
                      )}
                      
                      {loading && (
                        <div className="flex items-center gap-2 py-4">
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span className="text-sm text-gray-400">Loading tables...</span>
                        </div>
                      )}
                      
                      {tables.length > 0 && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-semibold text-white">Tables ({tables.length})</h4>
                          {tables.map((table) => (
                            <div
                              key={table.id}
                              className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                                selectedTable === table.id
                                  ? "border-blue-500 bg-blue-500/10"
                                  : "border-gray-700 hover:border-gray-600 bg-gray-800/30"
                              }`}
                              onClick={() => setSelectedTable(table.id)}
                            >
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                  <Table2 className="w-4 h-4 text-blue-400" />
                                  <span className="text-white font-medium">{table.tableName}</span>
                                </div>
                                <div className="flex items-center gap-3 text-xs text-gray-400">
                                  <span>{table.columnCount} columns</span>
                                  <span>{table.rowCount} rows</span>
                                  <Badge variant="secondary" className="text-xs">
                                    {table.status}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </Card>
      )}

      {/* Table Data Viewer */}
      {selectedTable && (
        <Card className="p-6 border-blue-500/30">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white">
              Table: {tables.find(t => t.id === selectedTable)?.tableName}
            </h3>
            <div className="flex gap-2">
              {columns.length === 0 && (
                <Button
                  onClick={() => dumpColumns(selectedTable)}
                  size="sm"
                  variant="outline"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Dump Columns
                </Button>
              )}
              {columns.length > 0 && data.length === 0 && (
                <Button
                  onClick={() => dumpData(selectedTable)}
                  size="sm"
                  variant="outline"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Dump Data
                </Button>
              )}
              {data.length > 0 && (
                <Button
                  onClick={exportToCSV}
                  size="sm"
                  className="bg-green-600 hover:bg-green-700"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export CSV
                </Button>
              )}
            </div>
          </div>

          {/* Columns */}
          {columns.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-semibold text-gray-400 mb-2">
                Columns ({columns.length})
              </h4>
              <div className="flex flex-wrap gap-2">
                {columns.map((col) => (
                  <Badge key={col.id} variant="outline" className="text-xs">
                    {col.columnName}
                    <span className="ml-1 text-gray-500">({col.dataType})</span>
                    {col.columnKey && (
                      <span className="ml-1 text-blue-400">[{col.columnKey}]</span>
                    )}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Data Table */}
          {data.length > 0 && columns.length > 0 && (
            <ScrollArea className="h-[500px] rounded-lg border border-gray-700">
              <Table>
                <TableHeader className="bg-gray-800/50 sticky top-0">
                  <TableRow>
                    <TableHead className="text-gray-300">#</TableHead>
                    {columns.map((col) => (
                      <TableHead key={col.id} className="text-gray-300">
                        {col.columnName}
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.map((row) => (
                    <TableRow key={row.id} className="hover:bg-gray-800/30">
                      <TableCell className="text-gray-400 font-mono text-xs">
                        {row.rowIndex}
                      </TableCell>
                      {columns.map((col) => (
                        <TableCell key={col.id} className="text-white font-mono text-sm">
                          {JSON.stringify(row.rowData[col.columnName])}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          )}
        </Card>
      )}
    </div>
  );
}
