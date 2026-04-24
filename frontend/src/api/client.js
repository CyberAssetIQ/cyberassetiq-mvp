import axios from "axios";

export const api = axios.create({
  baseURL: "http://192.168.0.179:8000",
  headers: {
    "const API_KEY = import.meta.env.VITE_API_KEY || "",
    "const TENANT_ID = import.meta.env.VITE_TENANT_ID || "tenant-001",
  }
});

export async function getDashboardSummary() {
  const res = await api.get("/api/dashboard/summary");
  return res.data;
}

export async function getAlerts() {
  const res = await api.get("/api/ai/alerts");
  return res.data;
}

