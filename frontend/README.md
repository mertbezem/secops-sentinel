# SecOps Sentinel — Ön Yüz Yol Haritası & Faz 2 Notları

Bu dizin, **Faz 2 (React SPA Dashboard)** için mimari notları içermektedir.

Faz 1 (MVP) kapsamında, `demo/index.html` ve `backend/app/static/` altında bağımsız, sıfır derleme gerektiren, ultra modern bir Vanilla JS + Chart.js arayüzü sunulmaktadır.

## 🚀 Faz 2 İçin Planlanan Özellikler:
- **Çatı (Framework)**: React 18 + TypeScript + Vite.
- **Durum & Veri Yönetimi**: Asenkron sunucu durumu için TanStack Query (React Query).
- **Tip Güvenliği**: FastAPI'den `openapi-typescript` ile otomatik TypeScript tip üretimi.
- **Arayüz Bileşenleri**: TailwindCSS + Lucide Icons + Recharts ile etkileşimli SIEM zaman serisi grafikleri ve MITRE ATT&CK ısı haritaları.
- **Gerçek Zamanlı Akış**: Canlı log akışı ve anlık alarm bildirimleri için WebSocket entegrasyonu.
