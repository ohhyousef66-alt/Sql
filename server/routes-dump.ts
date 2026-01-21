/**
 * Dump API Routes
 * Endpoints for database dumping and data extraction
 */

import type { Express } from "express";
import { z } from "zod";
import { storage } from "./storage";

export function setupDumpRoutes(app: Express) {
  /**
   * GET /api/dump/databases
   * Get all extracted databases (optionally filtered by scanId)
   */
  app.get("/api/dump/databases", async (req, res) => {
    try {
      const { scanId } = req.query;
      
      const databases = await storage.getExtractedDatabases(
        scanId ? parseInt(scanId as string) : undefined
      );

      // Get tables for each database
      const result = await Promise.all(
        databases.map(async (db) => {
          const tables = await storage.getExtractedTables(db.id);
          
          // Get column count and row count for each table
          const tablesWithInfo = await Promise.all(
            tables.map(async (table) => {
              const columns = await storage.getExtractedColumns(table.id);
              
              // Estimate row count (get max from any column's data length)
              let rowCount = 0;
              for (const col of columns) {
                const data = await storage.getExtractedData(col.id);
                rowCount = Math.max(rowCount, data.length);
              }
              
              return {
                id: table.id,
                name: table.name,
                columnCount: columns.length,
                rowCount,
                columns: [], // Empty initially, loaded on demand
              };
            })
          );

          return {
            id: db.id,
            vulnerabilityId: db.vulnerabilityId,
            name: db.name,
            tables: tablesWithInfo,
          };
        })
      );

      res.json(result);
    } catch (error) {
      console.error("Error getting databases:", error);
      res.status(500).json({ error: "Failed to get databases" });
    }
  });

  /**
   * GET /api/dump/databases/:dbId/tables/:tableName/data
   * Get all data for a specific table
   */
  app.get("/api/dump/databases/:dbId/tables/:tableName/data", async (req, res) => {
    try {
      const { dbId, tableName } = req.params;
      
      // Get table
      const tables = await storage.getExtractedTables(parseInt(dbId));
      const table = tables.find(t => t.name === tableName);
      
      if (!table) {
        return res.status(404).json({ error: "Table not found" });
      }

      // Get all columns with their data
      const columns = await storage.getExtractedColumns(table.id);
      
      const columnsWithData = await Promise.all(
        columns.map(async (col) => {
          const data = await storage.getExtractedData(col.id);
          return {
            id: col.id,
            name: col.name,
            type: col.type,
            data: data.map(d => d.value),
          };
        })
      );

      res.json({ columns: columnsWithData });
    } catch (error) {
      console.error("Error getting table data:", error);
      res.status(500).json({ error: "Failed to get table data" });
    }
  });
}
