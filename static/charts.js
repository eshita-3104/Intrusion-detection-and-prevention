console.log("charts.js is running");

// Line Chart for Anomaly Scores
const ctxLine = document.getElementById('anomalyChart').getContext('2d');
const anomalyChart = new Chart(ctxLine, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Anomaly Score',
                borderColor: '#f87171', // Red
                backgroundColor: 'rgba(248, 113, 113, 0.2)',
                data: [],
                fill: false,
                tension: 0.1
            },
            {
                label: 'Anomaly Threshold (-0.01)',
                borderColor: '#a1a1aa', // Gray
                data: [],
                borderDash: [5, 5],
                pointRadius: 0,
                fill: false
            }
        ]
    },
    options: {
        scales: {
            y: {
                beginAtZero: false,
                min: -1,
                max: 1,
                title: {
                    display: true,
                    text: 'Score (1 = Normal, -1 = Anomaly)',
                    color: '#d1d5db'
                },
                grid: {
                    color: '#4b5563'
                },
                ticks: {
                    color: '#d1d5db'
                }
            },
            x: {
                title: {
                    display: true,
                    text: 'Timestamp',
                    color: '#d1d5db'
                },
                grid: {
                    color: '#4b5563'
                },
                ticks: {
                    color: '#d1d5db',
                    maxRotation: 45,
                    minRotation: 45
                }
            }
        },
        plugins: {
            legend: {
                labels: {
                    color: '#d1d5db'
                }
            }
        }
    }
});

// Pie Chart for Anomaly Distribution
const ctxPie = document.getElementById('anomalyPieChart').getContext('2d');
const anomalyPieChart = new Chart(ctxPie, {
    type: 'pie',
    data: {
        labels: ['Normal', 'Anomaly'],
        datasets: [{
            data: [0, 0], // Will be updated with actual counts
            backgroundColor: ['#34d399', '#f87171'], // Green for Normal, Red for Anomaly
            borderColor: '#1f2937',
            borderWidth: 1
        }]
    },
    options: {
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: '#d1d5db'
                }
            }
        }
    }
});

async function fetchData() {
    try {
        console.log("Fetching data from /api/data");
        const response = await fetch('/api/data');
        if (!response.ok) throw new Error('Network response was not ok');
        const data = await response.json();
        console.log("Received data:", data);

        // Update Line Chart
        const latestData = data.slice(-50); // Limit to latest 50 entries for the line chart
        anomalyChart.data.labels = latestData.map(entry => entry.timestamp);
        anomalyChart.data.datasets[0].data = latestData.map(entry => entry.score);
        anomalyChart.data.datasets[1].data = latestData.map(() => -0.01); // Threshold line
        anomalyChart.update();

        // Update Pie Chart
        const normalCount = data.filter(entry => !entry.anomaly).length;
        const anomalyCount = data.filter(entry => entry.anomaly).length;
        anomalyPieChart.data.datasets[0].data = [normalCount, anomalyCount];
        anomalyPieChart.update();

        // Calculate False Positives
        // A false positive is when score <= -0.01 (predicted anomaly) but anomaly is false (overridden to normal)
        const falsePositives = data.filter(entry => entry.score <= -0.01 && !entry.anomaly).length;
        document.getElementById('falsePositiveCounter').textContent = `False Positives: ${falsePositives}`;

        // Update Table
        const tableBody = document.getElementById('packetTableBody');
        tableBody.innerHTML = ''; // Clear existing rows
        latestData.forEach(entry => {
            const row = document.createElement('tr');
            row.className = entry.anomaly ? 'bg-red-900/30' : 'bg-green-900/30';
            row.innerHTML = `
                <td class="px-4 py-2">${entry.timestamp}</td>
                <td class="px-4 py-2">${entry.src}</td>
                <td class="px-4 py-2">${entry.dst}</td>
                <td class="px-4 py-2">${entry.topic}</td>
                <td class="px-4 py-2">${entry.payload}</td>
                <td class="px-4 py-2">${entry.score.toFixed(4)}</td>
                <td class="px-4 py-2">${entry.payload_length}</td>
                <td class="px-4 py-2">${entry.inter_arrival.toFixed(2)}</td>
                <td class="px-4 py-2">${(entry.packet_rate || 0).toFixed(2)}</td>
                <td class="px-4 py-2 font-semibold ${entry.anomaly ? 'text-red-400' : 'text-green-400'}">
                    ${entry.anomaly ? '🔴 Anomaly' : '🟢 Normal'}
                </td>
            `;
            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

// Initial fetch
fetchData();
// Refresh every 1 second
setInterval(fetchData, 1000);