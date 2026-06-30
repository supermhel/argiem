FROM nginx:alpine
# Static single-file dashboard.
COPY services/ws7-dashboard /usr/share/nginx/html
# Reverse-proxy config: serves the static files AND proxies /api/alerts to
# OpenSearch (same-origin -> no CORS). Lives outside the html root so it is not
# also served as a static file.
RUN rm -f /usr/share/nginx/html/nginx.conf /usr/share/nginx/html/Dockerfile
COPY services/ws7-dashboard/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
# DX4: alerts come LIVE from /api/alerts (proxied to OpenSearch). Inventory is
# fetched from WS-6 via window.INVENTORY_API. Both fall back to mocks/mock_data.js.
