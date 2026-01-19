import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, buildUrl } from "@shared/routes";
import { apiRequest } from "@/lib/queryClient";
import type { InsertScan, Scan } from "@shared/schema";
import { useToast } from "@/hooks/use-toast";
import { z } from "zod";

// Helper to construct URLs
const getScansUrl = api.scans.list.path;
const createScanUrl = api.scans.create.path;

export function useScans() {
  return useQuery({
    queryKey: [getScansUrl],
    queryFn: async () => {
      const res = await fetch(getScansUrl, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch scans");
      return api.scans.list.responses[200].parse(await res.json());
    },
    refetchInterval: 5000, // Poll for status updates
  });
}

export function useScan(id: number) {
  return useQuery({
    queryKey: [api.scans.get.path, id],
    queryFn: async () => {
      const url = buildUrl(api.scans.get.path, { id });
      const res = await fetch(url, { credentials: "include" });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error("Failed to fetch scan details");
      return api.scans.get.responses[200].parse(await res.json());
    },
    refetchInterval: (query) => {
      const data = query.state.data as Scan | undefined;
      // Stop polling if completed or failed
      if (data && (data.status === "completed" || data.status === "failed" || data.status === "cancelled")) {
        return false;
      }
      return 500; // WAR ROOM: Ultra-fast 500ms polling for real-time attack telemetry
    },
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: InsertScan) => {
      const validated = api.scans.create.input.parse(data);
      const res = await fetch(createScanUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validated),
        credentials: "include",
      });
      
      if (!res.ok) {
        if (res.status === 400) {
          const error = api.scans.create.responses[400].parse(await res.json());
          throw new Error(error.message);
        }
        throw new Error("Failed to start scan");
      }
      return api.scans.create.responses[201].parse(await res.json());
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [getScansUrl] });
    },
  });
}

export function useScanVulnerabilities(scanId: number) {
  return useQuery({
    queryKey: [api.scans.getVulnerabilities.path, scanId],
    queryFn: async () => {
      const url = buildUrl(api.scans.getVulnerabilities.path, { id: scanId });
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch vulnerabilities");
      return api.scans.getVulnerabilities.responses[200].parse(await res.json());
    },
    refetchInterval: 500, // WAR ROOM: 500ms polling for live vulnerability feed
  });
}

export function useChildScans(parentId: number, enabled: boolean = true) {
  return useQuery({
    queryKey: [api.scans.getChildren.path, parentId],
    queryFn: async () => {
      const url = buildUrl(api.scans.getChildren.path, { id: parentId });
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch child scans");
      return api.scans.getChildren.responses[200].parse(await res.json());
    },
    enabled,
    refetchInterval: 2000, // Poll for child status updates
  });
}

export function useScanLogs(scanId: number) {
  return useQuery({
    queryKey: [api.scans.getLogs.path, scanId],
    queryFn: async () => {
      const url = buildUrl(api.scans.getLogs.path, { id: scanId });
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch logs");
      return api.scans.getLogs.responses[200].parse(await res.json());
    },
    refetchInterval: 500, // WAR ROOM: 500ms polling for live console
  });
}

export function useTrafficLogs(scanId: number, limit: number = 500) {
  return useQuery({
    queryKey: [api.scans.getTrafficLogs.path, scanId, limit],
    queryFn: async () => {
      const url = buildUrl(api.scans.getTrafficLogs.path, { id: scanId }) + `?limit=${limit}`;
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch traffic logs");
      return api.scans.getTrafficLogs.responses[200].parse(await res.json());
    },
    refetchInterval: 500, // WAR ROOM: 500ms polling for live traffic analysis
  });
}

export function useExportReport() {
  return useMutation({
    mutationFn: async (scanId: number) => {
      const url = buildUrl(api.scans.export.path, { id: scanId });
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to generate report");
      
      // Handle file download
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.setAttribute('download', `scan-report-${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    },
  });
}

export function useCancelScan() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const url = buildUrl(api.scans.cancel.path, { id });
      const res = await apiRequest("POST", url);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [getScansUrl] });
      // Also invalidate specific scan query
      queryClient.invalidateQueries({ queryKey: [api.scans.get.path] });
      toast({
        title: "Scan Cancelled",
        description: "The vulnerability scan has been terminated.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Cancellation Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}
