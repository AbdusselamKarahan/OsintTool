// Modal Controls
const scanModal = document.getElementById('scanModal');
const resultsModal = document.getElementById('resultsModal');
const openScanModalBtn = document.getElementById('openScanModal');
const closeButtons = document.querySelectorAll('.close-modal');
const loadingOverlay = document.querySelector('.loading-overlay');

// Open scan modal
openScanModalBtn.addEventListener('click', () => {
    scanModal.style.display = 'block';
});

// Close modals
closeButtons.forEach(button => {
    button.addEventListener('click', () => {
        scanModal.style.display = 'none';
        resultsModal.style.display = 'none';
    });
});

// Close modals when clicking outside
window.addEventListener('click', (e) => {
    if (e.target === scanModal) scanModal.style.display = 'none';
    if (e.target === resultsModal) resultsModal.style.display = 'none';
});

// Tab Controls
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabButtons.forEach(button => {
    button.addEventListener('click', () => {
        // Remove active class from all buttons and contents
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabContents.forEach(content => content.classList.remove('active'));

        // Add active class to clicked button and corresponding content
        button.classList.add('active');
        document.getElementById(button.dataset.tab).classList.add('active');
    });
});

// Scan Forms
const forms = {
    subdomain: document.getElementById('subdomainForm'),
    directory: document.getElementById('directoryForm'),
    js: document.getElementById('jsForm')
};

// Store scan results
let scanHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');
updateScanResults();
updateStats();

// Handle form submissions
forms.subdomain.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await startScan('subdomain', {
        target_domain: formData.get('target_domain')
    });
});

forms.directory.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await startScan('directory', {
        target_url: formData.get('target_url')
    });
});

forms.js.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await startScan('js', {
        target_url: formData.get('target_url')
    });
});

async function startScan(type, data) {
    try {
        // Show loading overlay
        loadingOverlay.style.display = 'flex';
        scanModal.style.display = 'none';

        // Send scan request
        const endpoints = {
            subdomain: '/api/scan/subdomains',
            directory: '/api/scan/directories',
            js: '/api/analyze/js'
        };

        const response = await fetch(endpoints[type], {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            // Add to scan history
            const scanResult = {
                id: Date.now(),
                type: type,
                target: data.target_domain || data.target_url,
                status: 'completed',
                results: result,
                date: new Date().toISOString()
            };

            scanHistory.unshift(scanResult);
            localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
            updateScanResults();
            updateStats();
            showResults(scanResult);
        } else {
            throw new Error(result.error || 'An error occurred during scanning');
        }
    } catch (error) {
        alert(error.message);
    } finally {
        loadingOverlay.style.display = 'none';
    }
}

function updateScanResults() {
    const tbody = document.getElementById('scanResults');
    tbody.innerHTML = scanHistory.map(scan => `
        <tr>
            <td>${scan.target}</td>
            <td>${getScanTypeName(scan.type)}</td>
            <td><span class="status ${scan.status}">${getStatusName(scan.status)}</span></td>
            <td>${getResultsSummary(scan)}</td>
            <td>${new Date(scan.date).toLocaleDateString('tr-TR')}</td>
            <td>
                <button class="action-btn view-btn" onclick="showResults(${scan.id})">
                    <span class="material-icons">visibility</span>
                    Görüntüle
                </button>
                <button class="action-btn delete-btn" onclick="deleteScan(${scan.id})">
                    <span class="material-icons">delete</span>
                    Sil
                </button>
            </td>
        </tr>
    `).join('');
}

function getScanTypeName(type) {
    const types = {
        subdomain: 'Subdomain',
        directory: 'Dizin',
        js: 'JS Analizi'
    };
    return types[type] || type;
}

function getStatusName(status) {
    const statuses = {
        completed: 'Tamamlandı',
        'in-progress': 'Devam Ediyor',
        failed: 'Başarısız'
    };
    return statuses[status] || status;
}

function getResultsSummary(scan) {
    if (scan.type === 'subdomain') {
        return `${scan.results.subdomains?.length || 0} subdomain`;
    } else if (scan.type === 'directory') {
        return `${scan.results.directories?.length || 0} dizin`;
    } else if (scan.type === 'js') {
        return `${scan.results.js_files?.length || 0} JS dosyası`;
    }
    return '0 sonuç';
}

function showResults(scanId) {
    const scan = scanHistory.find(s => s.id === scanId);
    if (!scan) return;

    const resultsContainer = document.getElementById('resultsContainer');
    let resultsHTML = '';

    if (scan.type === 'subdomain') {
        resultsHTML = `
            <h3>Bulunan Subdomainler (${scan.results.total_count})</h3>
            <p>Kullanılan Araçlar: ${scan.results.tools_used.join(', ')}</p>
            ${scan.results.subdomains.map(subdomain => `
                <div class="result-item">
                    <span><span class="material-icons">public</span>${subdomain}</span>
                    <a href="http://${subdomain}" target="_blank" class="action-btn view-btn">
                        <span class="material-icons">open_in_new</span>
                        Aç
                    </a>
                </div>
            `).join('')}
        `;
    } else if (scan.type === 'directory') {
        resultsHTML = `
            <h3>Bulunan Dizinler</h3>
            ${scan.results.directories.map(dir => `
                <div class="result-item">
                    <span><span class="material-icons">folder</span>${dir.url}</span>
                    <span class="status ${dir.status}">${getStatusName(dir.status)}</span>
                </div>
            `).join('')}
        `;
    } else if (scan.type === 'js') {
        resultsHTML = `
            <h3>JS Dosya Analizi</h3>
            ${scan.results.js_files.map(file => `
                <div class="result-item">
                    <span><span class="material-icons">code</span>${file}</span>
                </div>
            `).join('')}
        `;
    }

    resultsContainer.innerHTML = resultsHTML;
    resultsModal.style.display = 'block';
}

function deleteScan(scanId) {
    if (confirm('Are you sure you want to delete this scan record?')) {
        scanHistory = scanHistory.filter(scan => scan.id !== scanId);
        localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
        updateScanResults();
        updateStats();
    }
}

function updateStats() {
    const stats = {
        totalScans: scanHistory.length,
        totalSubdomains: scanHistory.reduce((total, scan) => {
            if (scan.type === 'subdomain') {
                return total + (scan.results.subdomains?.length || 0);
            }
            return total;
        }, 0),
        totalVulnerabilities: scanHistory.reduce((total, scan) => {
            if (scan.type === 'js') {
                return total + (scan.results.vulnerabilities?.length || 0);
            }
            return total;
        }, 0)
    };

    document.querySelectorAll('.stat-value')[0].textContent = stats.totalScans;
    document.querySelectorAll('.stat-value')[1].textContent = stats.totalSubdomains;
    document.querySelectorAll('.stat-value')[2].textContent = stats.totalVulnerabilities;
}

// Update stats every 5 seconds (simulating real-time data)
setInterval(updateStats, 5000); 