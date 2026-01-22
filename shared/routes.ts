import { z } from "zod";
import { insertScanSchema, scans, vulnerabilities, scanLogs, trafficLogs, uploadedFiles, stagedTargets, stageRuns } from "./schema";

export const errorSchemas = {
  validation: z.object({
    message: z.string(),
  }),
  notFound: z.object({
    message: z.string(),
  }),
  internal: z.object({
    message: z.string(),
  }),
};

export const api = {
  scans: {
    list: {
      method: "GET" as const,
      path: "/api/scans",
      responses: {
        200: z.array(z.custom<typeof scans.$inferSelect>()),
      },
    },
    create: {
      method: "POST" as const,
      path: "/api/scans",
      input: insertScanSchema,
      responses: {
        201: z.custom<typeof scans.$inferSelect>(),
        400: errorSchemas.validation,
      },
    },
    get: {
      method: "GET" as const,
      path: "/api/scans/:id",
      responses: {
        200: z.custom<typeof scans.$inferSelect>(),
        404: errorSchemas.notFound,
      },
    },
    getVulnerabilities: {
      method: "GET" as const,
      path: "/api/scans/:id/vulnerabilities",
      responses: {
        200: z.array(z.custom<typeof vulnerabilities.$inferSelect>()),
        404: errorSchemas.notFound,
      },
    },
    getLogs: {
      method: "GET" as const,
      path: "/api/scans/:id/logs",
      responses: {
        200: z.array(z.custom<typeof scanLogs.$inferSelect>()),
        404: errorSchemas.notFound,
      },
    },
    getTrafficLogs: {
      method: "GET" as const,
      path: "/api/scans/:id/traffic",
      responses: {
        200: z.array(z.custom<typeof trafficLogs.$inferSelect>()),
        404: errorSchemas.notFound,
      },
    },
    export: {
      method: "GET" as const,
      path: "/api/scans/:id/export",
      responses: {
        200: z.any(), // PDF Buffer
        404: errorSchemas.notFound,
      },
    },
    cancel: {
      method: "POST" as const,
      path: "/api/scans/:id/cancel",
      responses: {
        200: z.custom<typeof scans.$inferSelect>(),
        404: errorSchemas.notFound,
      },
    },
    batch: {
      method: "POST" as const,
      path: "/api/scans/batch",
      input: z.object({
        targetUrls: z.array(z.string().url()).min(1).max(50000), // Support up to 50k URLs
        scanMode: z.enum(["sqli"]).default("sqli"),
        threads: z.number().min(1).max(50).default(10),
      }),
      responses: {
        201: z.object({
          parentScanId: z.number(),
          childScanIds: z.array(z.number()),
        }),
        400: errorSchemas.validation,
      },
    },
    getChildren: {
      method: "GET" as const,
      path: "/api/scans/:id/children",
      responses: {
        200: z.array(z.custom<typeof scans.$inferSelect>()),
        404: errorSchemas.notFound,
      },
    },
    getEnumerationResults: {
      method: "GET" as const,
      path: "/api/scans/:id/enumeration",
      responses: {
        200: z.array(z.object({
          id: z.number(),
          databaseName: z.string(),
          dbType: z.string(),
          extractionMethod: z.string(),
          tableCount: z.number(),
          status: z.string(),
          extractedAt: z.date(),
          tables: z.array(z.object({
            id: z.number(),
            tableName: z.string(),
            columnCount: z.number(),
            status: z.string(),
            extractedAt: z.date(),
            columns: z.array(z.object({
              id: z.number(),
              columnName: z.string(),
              dataType: z.string().nullable(),
              extractedAt: z.date(),
            })),
          })),
        })),
        404: errorSchemas.notFound,
      },
    },
  },
};

export function buildUrl(path: string, params?: Record<string, string | number>): string {
  let url = path;
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (url.includes(`:${key}`)) {
        url = url.replace(`:${key}`, String(value));
      }
    });
  }
  return url;
}
