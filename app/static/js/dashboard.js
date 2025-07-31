document.addEventListener('DOMContentLoaded', async () => {
  await Promise.all([
    loadSummaryStats(),
    loadCategoryChart(),
    loadCountryChart(),
    loadTrendChart(),
    loadMap()
  ]);
});

const defaultOptions = {
  responsive: true,
  plugins: {
    legend: {
      labels: { color: '#fff' }
    }
  },
  scales: {
    x: { ticks: { color: '#fff' } },
    y: { ticks: { color: '#fff' } }
  }
};

// ✅ FIXED: Fetch correct summary stats
async function loadSummaryStats() {
  const res = await fetch('/api/summary/stats');
  const data = await res.json();

  document.getElementById('totalIPs').textContent = data.total_ips;
  document.getElementById('totalCountries').textContent = data.total_countries;
  document.getElementById('totalISPs').textContent = data.total_isps;
  document.getElementById('lastSeen').textContent = data.last_seen || 'N/A';
}

async function loadCategoryChart() {
  const res = await fetch('/api/summary/abuse_categories');
  const data = await res.json();
  const ctx = document.getElementById('categoryChart').getContext('2d');

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d => d[0]),
      datasets: [{
        label: 'IPs',
        data: data.map(d => d[1]),
        backgroundColor: [
          '#dc2626', '#f87171', '#b91c1c', '#ef4444', '#7f1d1d',
          '#fca5a5', '#991b1b', '#fecaca', '#450a0a', '#fee2e2'
        ]
      }]
    },
    options: {
      ...defaultOptions,
      cutout: '65%'
    }
  });
}

async function loadCountryChart() {
  const res = await fetch('/api/summary/countries');
  const data = await res.json();
  const ctx = document.getElementById('countryChart').getContext('2d');

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d[0]),
      datasets: [{
        label: 'IPs',
        data: data.map(d => d[1]),
        backgroundColor: 'rgba(220, 38, 38, 0.7)'
      }]
    },
    options: defaultOptions
  });
}

async function loadTrendChart() {
  const res = await fetch('/api/summary/daily_trend');
  const data = await res.json();
  const ctx = document.getElementById('trendChart').getContext('2d');

  new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map(d => d[0]),
      datasets: [{
        label: 'Threats per Day',
        data: data.map(d => d[1]),
        borderColor: '#ffffff',
        backgroundColor: '#dc2626',
        tension: 0.3
      }]
    },
    options: defaultOptions
  });
}

async function loadMap() {
  const res = await fetch('/api/summary/map');
  const data = await res.json();

  const map = L.map('threatMap').setView([20.5937, 78.9629], 3);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
  }).addTo(map);

  const geoCoder = async (city, country) => {
    try {
      const r = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(city + ', ' + country)}`);
      const loc = await r.json();
      if (loc && loc.length > 0) return [parseFloat(loc[0].lat), parseFloat(loc[0].lon)];
    } catch { }
    return null;
  };

  for (const [ip, country, city] of data) {
    if (!city || !country) continue;
    const coords = await geoCoder(city, country);
    if (coords) {
      L.circleMarker(coords, {
        radius: 6,
        color: '#dc2626',
        fillColor: '#dc2626',
        fillOpacity: 0.8
      }).addTo(map).bindPopup(`<b>${ip}</b><br>${city}, ${country}`);
    }
  }
}
