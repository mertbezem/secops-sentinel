# SecOps Sentinel — Frontend Roadmap & Phase 2 Notes

This directory contains notes for **Phase 2 (React SPA Dashboard)**.

In Phase 1 (MVP), the application provides a zero-build, standalone Vanilla JS dashboard located at `demo/index.html`.

## Phase 2 Planned Features:
- **Framework**: React 18 + TypeScript + Vite.
- **State & Data Fetching**: TanStack Query (React Query) for async server state management.
- **Type Safety**: Automatic TypeScript type generation from FastAPI via `openapi-typescript`.
- **UI Components**: TailwindCSS + Lucide Icons + Recharts for interactive SIEM time-series graphs and MITRE ATT&CK heatmaps.
- **Realtime**: WebSocket stream integration for live log ingestion and instant alert notifications.
