// SmartSploit Dashboard JavaScript

class SmartSploitDashboard {
    constructor() {
        this.charts = {};
        this.intervalId = null;
        this.isVisible = true;
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadDashboardData();
        this.startAutoRefresh();
        this.initializeCharts();
        this.handleVisibilityChange();
    }
    
    setupEventListeners() {
        // Mobile menu toggle
        const menuToggle = document.querySelector('.menu-toggle');
        const sidebar = document.querySelector('.sidebar');
        
        if (menuToggle && sidebar) {
            menuToggle.addEventListener('click', () => {
                sidebar.classList.toggle('open');
            });
        }
        
        // Quick scan button
        const quickScanBtn = document.querySelector('#quick-scan-btn');
        if (quickScanBtn) {
            quickScanBtn.addEventListener('click', this.handleQuickScan.bind(this));
        }
        
        // Refresh button
        const refreshBtn = document.querySelector('#refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', this.loadDashboardData.bind(this));
        }
        
        // Console input
        const consoleInput = document.querySelector('#console-input');
        if (consoleInput) {
            consoleInput.addEventListener('keypress', this.handleConsoleInput.bind(this));
        }
    }
    
    handleVisibilityChange() {
        document.addEventListener('visibilitychange', () => {
            this.isVisible = !document.hidden;
            if (this.isVisible) {
                this.loadDashboardData();
            }
        });
    }
    
    async loadDashboardData() {
        try {
            await Promise.all([
                this.updateStats(),
                this.updateNetworkStatus(),
                this.updateRecentExploits(),
                this.updateVulnerabilityData()
            ]);
        } catch (error) {
            console.error('Error loading dashboard data:', error);
            this.showNotification('Error loading dashboard data', 'error');
        }
    }
    
    async updateStats() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();
            
            if (data.success) {
                const stats = data.stats;
                this.updateMetricCard('active-modules', stats.active_modules);
                this.updateMetricCard('successful-exploits', stats.successful_exploits);
                this.updateMetricCard('active-sessions', stats.active_sessions);
                this.updateMetricCard('high-risk-contracts', stats.high_risk_contracts);
                this.updateMetricCard('medium-risk-contracts', stats.medium_risk_contracts);
                this.updateMetricCard('low-risk-contracts', stats.low_risk_contracts);
                
                // Update vulnerability chart
                if (this.charts.vulnerabilityChart) {
                    this.updateVulnerabilityChart(stats);
                }
            }
        } catch (error) {
            console.error('Error updating stats:', error);
        }
    }
    
    updateMetricCard(cardId, value) {
        const card = document.querySelector(`[data-metric="${cardId}"]`);
        if (card) {
            const valueElement = card.querySelector('.metric-value');
            if (valueElement) {
                // Animate value change
                this.animateValue(valueElement, parseInt(valueElement.textContent) || 0, value);
            }
        }
    }
    
    animateValue(element, start, end, duration = 1000) {
        const range = end - start;
        const increment = range / (duration / 16);
        let current = start;
        
        const timer = setInterval(() => {
            current += increment;
            if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
                current = end;
                clearInterval(timer);
            }
            element.textContent = Math.floor(current);
        }, 16);
    }
    
    async updateNetworkStatus() {
        try {
            const response = await fetch('/api/network_status');
            const data = await response.json();
            
            if (data.success) {
                const statusContainer = document.querySelector('#network-status');
                if (statusContainer) {
                    statusContainer.innerHTML = this.renderNetworkStatus(data.networks);
                }
            }
        } catch (error) {
            console.error('Error updating network status:', error);
        }
    }
    
    renderNetworkStatus(networks) {
        return Object.entries(networks).map(([name, online]) => {
            const statusClass = online ? 'success' : 'error';
            const statusText = online ? 'Online' : 'Offline';
            const statusIcon = online ? '●' : '●';
            
            return `
                <div class="network-item d-flex justify-content-between align-items-center mb-2">
                    <span class="network-name">${name.charAt(0).toUpperCase() + name.slice(1)}</span>
                    <span class="badge badge-${statusClass}">
                        <span class="status-icon">${statusIcon}</span>
                        ${statusText}
                    </span>
                </div>
            `;
        }).join('');
    }
    
    async updateRecentExploits() {
        try {
            // Since we don't have real recent exploits, show placeholder
            const container = document.querySelector('#recent-exploits');
            if (container) {
                container.innerHTML = `
                    <div class="text-center text-muted p-4">
                        <i class="fas fa-shield-alt fa-2x mb-2"></i>
                        <p>No recent exploits</p>
                        <p class="small">Exploit results will appear here</p>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Error updating recent exploits:', error);
        }
    }
    
    async updateVulnerabilityData() {
        try {
            const response = await fetch('/api/targets?per_page=5');
            const data = await response.json();
            
            if (data.success && data.targets.length > 0) {
                const container = document.querySelector('#vulnerability-targets');
                if (container) {
                    container.innerHTML = this.renderVulnerabilityTargets(data.targets);
                }
            }
        } catch (error) {
            console.error('Error updating vulnerability data:', error);
        }
    }
    
    renderVulnerabilityTargets(targets) {
        return targets.map(target => {
            const riskClass = target.risk_level.toLowerCase();
            const riskColor = {
                high: 'error',
                medium: 'warning', 
                low: 'success'
            }[target.risk_level.toLowerCase()] || 'neutral';
            
            return `
                <div class="vulnerability-item mb-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <div class="contract-address font-mono">${this.truncateAddress(target.address)}</div>
                            <div class="network-name text-muted small">${target.network}</div>
                        </div>
                        <div class="text-right">
                            <span class="badge badge-${riskColor}">${target.risk_level}</span>
                            <div class="risk-score small text-muted mt-1">${(target.vulnerability_score * 100).toFixed(1)}%</div>
                        </div>
                    </div>
                    <div class="progress mt-2">
                        <div class="progress-bar ${riskColor}" style="width: ${target.vulnerability_score * 100}%"></div>
                    </div>
                </div>
            `;
        }).join('');
    }
    
    truncateAddress(address) {
        if (address.length <= 10) return address;
        return `${address.slice(0, 6)}...${address.slice(-4)}`;
    }
    
    initializeCharts() {
        this.initVulnerabilityChart();
        this.initExploitTrendChart();
    }
    
    initVulnerabilityChart() {
        const ctx = document.getElementById('vulnerability-chart');
        if (!ctx) return;
        
        this.charts.vulnerabilityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['High Risk', 'Medium Risk', 'Low Risk'],
                datasets: [{
                    data: [23, 47, 156],
                    backgroundColor: [
                        '#ea4335',
                        '#fbbc05', 
                        '#34a853'
                    ],
                    borderColor: '#1e2533',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#b4bcd0',
                            usePointStyle: true,
                            padding: 20
                        }
                    }
                },
                elements: {
                    arc: {
                        borderWidth: 0
                    }
                }
            }
        });
    }
    
    initExploitTrendChart() {
        const ctx = document.getElementById('exploit-trend-chart');
        if (!ctx) return;
        
        const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 400);
        gradient.addColorStop(0, 'rgba(0, 212, 255, 0.2)');
        gradient.addColorStop(1, 'rgba(0, 212, 255, 0)');
        
        this.charts.exploitTrendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Successful Exploits',
                    data: [12, 19, 3, 5, 2, 3],
                    borderColor: '#00d4ff',
                    backgroundColor: gradient,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: {
                            color: '#3a4458'
                        },
                        ticks: {
                            color: '#b4bcd0'
                        }
                    },
                    y: {
                        grid: {
                            color: '#3a4458'
                        },
                        ticks: {
                            color: '#b4bcd0'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#b4bcd0'
                        }
                    }
                }
            }
        });
    }
    
    updateVulnerabilityChart(stats) {
        if (this.charts.vulnerabilityChart) {
            this.charts.vulnerabilityChart.data.datasets[0].data = [
                stats.high_risk_contracts,
                stats.medium_risk_contracts,
                stats.low_risk_contracts
            ];
            this.charts.vulnerabilityChart.update();
        }
    }
    
    async handleQuickScan() {
        const addressInput = document.querySelector('#scan-address');
        if (!addressInput) return;
        
        const address = addressInput.value.trim();
        if (!address) {
            this.showNotification('Please enter a contract address', 'warning');
            return;
        }
        
        if (!this.isValidAddress(address)) {
            this.showNotification('Invalid Ethereum address format', 'error');
            return;
        }
        
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/scan_contract', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ address })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showNotification('Scan completed successfully', 'success');
                this.displayScanResults(data.scan_result);
                this.loadDashboardData(); // Refresh dashboard
            } else {
                this.showNotification(data.error || 'Scan failed', 'error');
            }
        } catch (error) {
            console.error('Scan error:', error);
            this.showNotification('Scan request failed', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    isValidAddress(address) {
        return /^0x[a-fA-F0-9]{40}$/.test(address);
    }
    
    displayScanResults(result) {
        // Display scan results in a modal or dedicated section
        const modal = this.createScanResultsModal(result);
        document.body.appendChild(modal);
        
        // Auto remove modal after 10 seconds
        setTimeout(() => {
            if (modal.parentNode) {
                modal.parentNode.removeChild(modal);
            }
        }, 10000);
    }
    
    createScanResultsModal(result) {
        const modal = document.createElement('div');
        modal.className = 'scan-results-modal';
        modal.innerHTML = `
            <div class="modal-overlay" onclick="this.parentElement.remove()"></div>
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Scan Results</h3>
                    <button class="modal-close" onclick="this.closest('.scan-results-modal').remove()">×</button>
                </div>
                <div class="modal-body">
                    ${this.renderScanResults(result)}
                </div>
            </div>
        `;
        
        // Add modal styles
        const style = document.createElement('style');
        style.textContent = `
            .scan-results-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: 10000;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .modal-overlay {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
            }
            .modal-content {
                position: relative;
                background: var(--bg-card);
                border: 1px solid var(--border-primary);
                border-radius: 12px;
                max-width: 600px;
                max-height: 80vh;
                overflow-y: auto;
                box-shadow: var(--shadow-lg);
            }
            .modal-header {
                padding: 1rem 1.5rem;
                border-bottom: 1px solid var(--border-primary);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .modal-close {
                background: none;
                border: none;
                color: var(--text-muted);
                font-size: 1.5rem;
                cursor: pointer;
            }
            .modal-body {
                padding: 1.5rem;
            }
        `;
        document.head.appendChild(style);
        
        return modal;
    }
    
    renderScanResults(result) {
        if (!result || !result.data) {
            return '<p class="text-muted">No scan data available</p>';
        }
        
        const data = result.data;
        
        return `
            <div class="scan-summary mb-3">
                <h4>Contract: ${data.contract_address || 'Unknown'}</h4>
                <p class="text-muted">Risk Level: <span class="badge badge-${this.getRiskBadgeClass(data.risk_level)}">${data.risk_level || 'Unknown'}</span></p>
                <p class="text-muted">Risk Score: ${data.risk_score ? (data.risk_score * 100).toFixed(1) + '%' : 'N/A'}</p>
            </div>
            
            ${data.vulnerabilities ? this.renderVulnerabilities(data.vulnerabilities) : ''}
            
            ${data.recommendations ? this.renderRecommendations(data.recommendations) : ''}
        `;
    }
    
    renderVulnerabilities(vulnerabilities) {
        const vulnEntries = Object.entries(vulnerabilities);
        if (vulnEntries.length === 0) {
            return '<p class="text-success">No vulnerabilities detected</p>';
        }
        
        return `
            <div class="vulnerabilities-section">
                <h5>Detected Vulnerabilities</h5>
                ${vulnEntries.map(([name, details]) => {
                    if (!details.detected) return '';
                    
                    return `
                        <div class="vulnerability-item mb-2 p-2" style="background: var(--bg-tertiary); border-radius: 6px;">
                            <div class="d-flex justify-content-between align-items-center">
                                <strong>${name.replace(/_/g, ' ').toUpperCase()}</strong>
                                <span class="badge badge-${this.getSeverityBadgeClass(details.severity)}">${details.severity}</span>
                            </div>
                            <p class="small text-muted mb-1">${details.description || 'No description'}</p>
                            <p class="small">Confidence: ${(details.confidence * 100).toFixed(1)}%</p>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }
    
    renderRecommendations(recommendations) {
        if (!recommendations || recommendations.length === 0) {
            return '';
        }
        
        return `
            <div class="recommendations-section mt-3">
                <h5>Security Recommendations</h5>
                <ul class="small">
                    ${recommendations.slice(0, 5).map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    getRiskBadgeClass(riskLevel) {
        switch ((riskLevel || '').toLowerCase()) {
            case 'high': return 'error';
            case 'medium': return 'warning';
            case 'low': return 'success';
            default: return 'neutral';
        }
    }
    
    getSeverityBadgeClass(severity) {
        switch ((severity || '').toLowerCase()) {
            case 'high': return 'error';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'neutral';
        }
    }
    
    async handleConsoleInput(event) {
        if (event.key !== 'Enter') return;
        
        const input = event.target;
        const command = input.value.trim();
        
        if (!command) return;
        
        // Add command to console output
        this.addConsoleOutput(`smartsploit > ${command}`, 'console-prompt');
        
        try {
            const response = await fetch('/api/console_command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ command })
            });
            
            const data = await response.json();
            
            if (data.success && data.output) {
                data.output.forEach(line => {
                    this.addConsoleOutput(line);
                });
            } else {
                this.addConsoleOutput('Command failed', 'text-error');
            }
        } catch (error) {
            this.addConsoleOutput('Network error', 'text-error');
        }
        
        input.value = '';
        this.scrollConsoleToBottom();
    }
    
    addConsoleOutput(text, className = '') {
        const output = document.querySelector('#console-output');
        if (!output) return;
        
        const line = document.createElement('div');
        line.className = `console-line ${className}`;
        line.textContent = text;
        
        output.appendChild(line);
        
        // Keep only last 100 lines
        while (output.children.length > 100) {
            output.removeChild(output.firstChild);
        }
    }
    
    scrollConsoleToBottom() {
        const consoleBody = document.querySelector('.console-body');
        if (consoleBody) {
            consoleBody.scrollTop = consoleBody.scrollHeight;
        }
    }
    
    showLoading(show) {
        const button = document.querySelector('#quick-scan-btn');
        if (!button) return;
        
        if (show) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner"></span> Scanning...';
        } else {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-search"></i> Quick Scan';
        }
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} notification`;
        notification.textContent = message;
        
        // Add notification styles
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            min-width: 300px;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'fadeOut 0.3s ease';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }
        }, 5000);
    }
    
    startAutoRefresh() {
        // Refresh every 30 seconds
        this.intervalId = setInterval(() => {
            if (this.isVisible) {
                this.updateStats();
                this.updateNetworkStatus();
            }
        }, 30000);
    }
    
    destroy() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
        }
        
        // Destroy charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.smartsploitDashboard = new SmartSploitDashboard();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.smartsploitDashboard) {
        window.smartsploitDashboard.destroy();
    }
});
