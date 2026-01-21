import { useState, useEffect } from "react";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Download, Database, Table2, Columns, Search } from "lucide-react";

interface DatabaseInfo {
  id: number;
  vulnerabilityId: number;
  name: string;
  tables: TableInfo[];
}

interface TableInfo {
  id: number;
  name: string;
  columnCount: number;
  rowCount: number;
  columns: ColumnInfo[];
}

interface ColumnInfo {
  id: number;
  name: string;
  type: string;
  data?: any[];
}

export default function Dump() {
  const searchQuery_params = window.location.search;
  const params = new URLSearchParams(searchQuery_params);
  const scanId = params.get("scanId");
  
  const [searchQuery, setSearchQuery] = useState("");
  const [databases, setDatabases] = useState<DatabaseInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDatabases();
  }, [scanId]);

  const loadDatabases = async () => {
    try {
      setLoading(true);
      let url = "/api/dump/databases";
      if (scanId) {
        url += `?scanId=${scanId}`;
      }

      const res = await fetch(url);
      if (!res.ok) throw new Error("Failed to load databases");

      const data = await res.json();
      setDatabases(data);
    } catch (error) {
      console.error("Error loading databases:", error);
    } finally {
      setLoading(false);
    }
  };

  const loadTableData = async (dbId: number, tableName: string) => {
    try {
      const res = await fetch(`/api/dump/databases/${dbId}/tables/${tableName}/data`);
      if (!res.ok) throw new Error("Failed to load table data");

      const data = await res.json();
      
      // Update database state with new table data
      setDatabases(prev => prev.map(db => {
        if (db.id === dbId) {
          return {
            ...db,
            tables: db.tables.map(t => 
              t.name === tableName 
                ? { ...t, columns: data.columns }
                : t
            )
          };
        }
        return db;
      }));
    } catch (error) {
      console.error("Error loading table data:", error);
    }
  };

  const exportToCSV = (table: TableInfo) => {
    if (!table.columns || table.columns.length === 0) return;

    // Create CSV header
    const headers = table.columns.map(c => c.name).join(",");
    
    // Get max row count
    const maxRows = Math.max(...table.columns.map(c => c.data?.length || 0));
    
    // Create CSV rows
    const rows: string[] = [];
    for (let i = 0; i < maxRows; i++) {
      const row = table.columns.map(c => {
        const value = c.data?.[i];
        return value !== undefined ? `"${value}"` : "";
      }).join(",");
      rows.push(row);
    }

    // Combine and download
    const csv = [headers, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${table.name}.csv`;
    a.click();
  };

  const filteredDatabases = databases.filter(db =>
    db.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold">Database Dump</h1>
            <p className="text-muted-foreground mt-2">
              استخراج وعرض البيانات المستخرجة من قواعد البيانات
            </p>
          </div>
          <Badge variant="outline" className="text-lg px-4 py-2">
            <Database className="w-4 h-4 mr-2" />
            {databases.length} Databases
          </Badge>
        </div>

        {/* Search */}
        <Card>
          <CardHeader>
            <div className="relative">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="ابحث عن database..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
          </CardHeader>
        </Card>

        {/* Databases */}
        {loading ? (
          <Card>
            <CardContent className="py-12 text-center">
              <p className="text-muted-foreground">Loading databases...</p>
            </CardContent>
          </Card>
        ) : filteredDatabases.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Database className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">
                {searchQuery ? "لا توجد databases مطابقة للبحث" : "لا توجد databases"}
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-4">
            {filteredDatabases.map((db) => (
              <Card key={db.id}>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Database className="w-5 h-5" />
                      {db.name}
                      <Badge variant="secondary">{db.tables.length} Tables</Badge>
                    </div>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <Accordion type="single" collapsible>
                    {db.tables.map((table) => (
                      <AccordionItem key={table.id} value={table.name}>
                        <AccordionTrigger>
                          <div className="flex items-center gap-2">
                            <Table2 className="w-4 h-4" />
                            {table.name}
                            <Badge variant="outline" className="ml-2">
                              {table.columnCount} Columns
                            </Badge>
                            <Badge variant="outline">
                              {table.rowCount} Rows
                            </Badge>
                          </div>
                        </AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-4">
                            {/* Load Data Button */}
                            {!table.columns || table.columns.length === 0 ? (
                              <Button
                                onClick={() => loadTableData(db.id, table.name)}
                                variant="outline"
                                size="sm"
                              >
                                Load Data
                              </Button>
                            ) : (
                              <>
                                {/* Export Button */}
                                <div className="flex justify-end">
                                  <Button
                                    onClick={() => exportToCSV(table)}
                                    variant="outline"
                                    size="sm"
                                  >
                                    <Download className="w-4 h-4 mr-2" />
                                    Export CSV
                                  </Button>
                                </div>

                                {/* Data Table */}
                                <div className="border rounded-lg overflow-x-auto">
                                  <table className="w-full">
                                    <thead className="bg-muted">
                                      <tr>
                                        {table.columns.map((col) => (
                                          <th
                                            key={col.id}
                                            className="px-4 py-2 text-left text-sm font-medium"
                                          >
                                            <div className="flex items-center gap-2">
                                              <Columns className="w-3 h-3" />
                                              {col.name}
                                              <Badge variant="secondary" className="text-xs">
                                                {col.type}
                                              </Badge>
                                            </div>
                                          </th>
                                        ))}
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {Array.from({
                                        length: Math.max(
                                          ...table.columns.map((c) => c.data?.length || 0)
                                        ),
                                      }).map((_, rowIndex) => (
                                        <tr
                                          key={rowIndex}
                                          className="border-t hover:bg-muted/50"
                                        >
                                          {table.columns.map((col) => (
                                            <td
                                              key={col.id}
                                              className="px-4 py-2 text-sm"
                                            >
                                              {col.data?.[rowIndex] !== undefined
                                                ? String(col.data[rowIndex])
                                                : "-"}
                                            </td>
                                          ))}
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              </>
                            )}
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    ))}
                  </Accordion>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
