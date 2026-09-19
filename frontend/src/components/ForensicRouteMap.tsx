import { useEffect, useRef } from 'react'
import L from 'leaflet'

interface ForensicRouteMapProps {
  originGeo?: any
  hops?: any[]
  geoCorrelation?: any
}

export default function ForensicRouteMap({
  originGeo,
  hops = [],
  geoCorrelation,
}: ForensicRouteMapProps) {
  const mapContainerRef = useRef<HTMLDivElement | null>(null)
  const mapInstanceRef = useRef<L.Map | null>(null)

  useEffect(() => {
    const el = mapContainerRef.current
    if (!el) return

    // Clean up existing instance if re-rendering
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove()
      mapInstanceRef.current = null
    }

    const map = L.map(el, {
      center: [20, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: false,
      preferCanvas: true,
    })
    mapInstanceRef.current = map

    L.tileLayer(
      'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
      {
        maxZoom: 16,
        attribution: '&copy; Esri',
      }
    ).addTo(map)

    const allMarkers: L.Layer[] = []
    const hopCoords: [number, number][] = []

    // 1. Plot Hop nodes
    const validHops = hops.filter(
      (h) => h.geo?.latitude && h.geo?.longitude && h.geo.latitude !== 0
    )

    validHops.forEach((h) => {
      const lat = h.geo.latitude
      const lon = h.geo.longitude
      hopCoords.push([lat, lon])

      const isSuspicious = h.suspicious
      const icon = L.divIcon({
        className: '',
        html: `<div style="width:22px;height:22px;background:${
          isSuspicious ? '#ef4444' : '#38bdf8'
        };color:#ffffff;border:2px solid #ffffff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:bold;box-shadow:0 0 8px rgba(0,0,0,0.6);">${h.hop_number}</div>`,
        iconSize: [22, 22],
        iconAnchor: [11, 11],
      })

      const marker = L.marker([lat, lon], { icon }).addTo(map)
      marker.bindPopup(
        `<div style="font-size:12px;font-family:'Inter',sans-serif;color:#1e293b;padding:2px;">` +
          `<strong>Hop #${h.hop_number}</strong><br/>` +
          `<strong>IP:</strong> ${h.ip || 'Unknown'}<br/>` +
          `<strong>Location:</strong> ${h.geo.city || '?'}, ${h.geo.country || '?'}<br/>` +
          `<strong>Host:</strong> ${h.from_host || 'Direct'}<br/>` +
          (h.delay_seconds ? `<strong>Delay:</strong> +${h.delay_seconds.toFixed(1)}s<br/>` : '') +
          (isSuspicious ? `<span style="color:#ef4444;font-weight:bold;">⚠️ Routing Anomaly</span>` : '') +
        `</div>`
      )
      allMarkers.push(marker)
    })

    // Draw routing hop line
    if (hopCoords.length > 1) {
      const hopLine = L.polyline(hopCoords, {
        color: '#38bdf8',
        weight: 3,
        opacity: 0.8,
      }).addTo(map)
      allMarkers.push(hopLine)
    }

    // 2. Plot Origin if not covered in hops
    const origLat = originGeo?.latitude
    const origLon = originGeo?.longitude
    if (origLat && origLon && origLat !== 0 && validHops.length === 0) {
      const isTor = originGeo.anonymizer?.is_tor
      const origIcon = L.divIcon({
        className: '',
        html: `<div style="width:18px;height:18px;background:${
          isTor ? '#9b59b6' : '#22c55e'
        };border:2px solid #ffffff;border-radius:50%;box-shadow:0 0 10px ${
          isTor ? '#9b59b6' : '#22c55e'
        };"></div>`,
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      })
      const origMarker = L.marker([origLat, origLon], { icon: origIcon }).addTo(map)
      origMarker.bindPopup(
        `<div style="font-size:12px;font-family:'Inter',sans-serif;color:#1e293b;padding:2px;">` +
          `<strong>Origin Sender MTA</strong><br/>` +
          `<strong>IP:</strong> ${originGeo.ip}<br/>` +
          `<strong>Location:</strong> ${originGeo.city || '?'}, ${originGeo.country || '?'}<br/>` +
          `<strong>ASN:</strong> ${originGeo.org || originGeo.asn || '?'}<br/>` +
          (isTor ? `<span style="color:#9b59b6;font-weight:bold;">⚠️ Active Tor Exit Node</span>` : '') +
        `</div>`
      )
      allMarkers.push(origMarker)
    }

    // 3. Plot Phishing Payload Targets & Cross-Border Divergence Arcs
    const targets = geoCorrelation?.targets || []
    targets.forEach((t: any) => {
      if (t.latitude && t.longitude && t.latitude !== 0) {
        const isTor = t.anonymizer?.is_tor
        const targetIcon = L.divIcon({
          className: '',
          html: `<div style="width:16px;height:16px;background:${
            isTor ? '#9b59b6' : '#ef4444'
          };border:2px solid #ffffff;transform:rotate(45deg);box-shadow:0 0 10px rgba(239,68,68,0.9);border-radius:2px;"></div>`,
          iconSize: [16, 16],
          iconAnchor: [8, 8],
        })
        const tMarker = L.marker([t.latitude, t.longitude], { icon: targetIcon }).addTo(map)
        tMarker.bindPopup(
          `<div style="font-size:12px;font-family:'Inter',sans-serif;color:#1e293b;padding:2px;">` +
            `<strong style="color:#ef4444;">🎯 Phishing Payload Server</strong><br/>` +
            `<strong>Host:</strong> ${t.hostname || t.ip}<br/>` +
            `<strong>Location:</strong> ${t.city || '?'}, ${t.country || '?'}<br/>` +
            `<strong>ASN:</strong> ${t.asn || t.org || 'Cloud'}<br/>` +
            `<strong>Distance:</strong> <span style="color:#e67e22;font-weight:bold;">${Math.round(
              t.distance_km || 0
            ).toLocaleString()} km from Sender</span><br/>` +
            (isTor ? `<span style="color:#9b59b6;font-weight:bold;">⚠️ Tor Hidden Infrastructure</span>` : '') +
          `</div>`
        )
        allMarkers.push(tMarker)

        // Draw cross-border divergence line from origin to payload server
        const startLat = origLat || (hopCoords[0] ? hopCoords[0][0] : null)
        const startLon = origLon || (hopCoords[0] ? hopCoords[0][1] : null)
        if (startLat && startLon) {
          const divLine = L.polyline(
            [
              [startLat, startLon],
              [t.latitude, t.longitude],
            ],
            {
              color: '#f97316',
              weight: 3,
              opacity: 0.85,
              dashArray: '8, 6',
            }
          ).addTo(map)
          divLine.bindPopup(
            `<div style="font-size:12px;font-family:'Inter',sans-serif;color:#1e293b;padding:2px;">` +
              `<strong style="color:#d97706;">⚡ Cross-Border Divergence Arc</strong><br/>` +
              `Distance: <strong style="color:#ef4444;">${Math.round(
                t.distance_km || 0
              ).toLocaleString()} km</strong><br/>` +
              `Sender (${originGeo?.country_code || '?'}) ➔ Phishing Host (${t.country_code})` +
            `</div>`
          )
          allMarkers.push(divLine)
        }
      }
    })

    // Fit bounds
    if (allMarkers.length > 0) {
      try {
        const group = L.featureGroup(allMarkers as any)
        map.fitBounds(group.getBounds().pad(0.3))
      } catch (e) {
        map.setView([20, 0], 2)
      }
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove()
        mapInstanceRef.current = null
      }
    }
  }, [originGeo, hops, geoCorrelation])

  const hasGeo =
    (originGeo?.latitude && originGeo.latitude !== 0) ||
    hops.some((h) => h.geo?.latitude && h.geo.latitude !== 0) ||
    (geoCorrelation?.targets || []).length > 0

  if (!hasGeo) return null

  return (
    <div className="card p-4 mb-3">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h6
          className="fw-bold text-uppercase mb-0"
          style={{ fontSize: '0.78rem', letterSpacing: '0.8px', color: 'var(--text-muted)' }}
        >
          <i className="fas fa-map-marked-alt text-info me-2"></i> Global Routing & Cross-Border Infrastructure Map
        </h6>
        <div className="d-flex align-items-center gap-3" style={{ fontSize: '0.72rem' }}>
          <span>
            <span
              style={{
                display: 'inline-block',
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: '#38bdf8',
                marginRight: 4,
              }}
            />
            Routing Hops
          </span>
          <span>
            <span
              style={{
                display: 'inline-block',
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: '#9b59b6',
                marginRight: 4,
              }}
            />
            Tor Exit
          </span>
          <span>
            <span
              style={{
                display: 'inline-block',
                width: 8,
                height: 8,
                transform: 'rotate(45deg)',
                background: '#ef4444',
                marginRight: 4,
              }}
            />
            Phishing Host
          </span>
          <span>
            <span
              style={{
                display: 'inline-block',
                width: 14,
                height: 2,
                background: '#f97316',
                marginRight: 4,
                verticalAlign: 'middle',
              }}
            />
            Divergence Vector
          </span>
        </div>
      </div>
      <div
        ref={mapContainerRef}
        style={{
          height: '320px',
          width: '100%',
          borderRadius: '8px',
          overflow: 'hidden',
          border: '1px solid var(--border)',
        }}
      />
    </div>
  )
}
