// Utility functions
const utils = {
    handleResponse(response) {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.message || `HTTP error! status: ${response.status}`); });
        }
        return response.json();
    },

    showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container') || document.createElement('div');
        container.id = 'notification-container';
        document.body.appendChild(container);

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            ${message}
            <button class="close-notification">&times;</button>
        `;
        container.appendChild(notification);

        notification.querySelector('.close-notification').onclick = () => notification.remove();
        setTimeout(() => notification.remove(), 5000);
    },

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    },

    toggleModal(modal, show) {
        if (modal) {
            modal.style.display = show ? 'block' : 'none';
        }
    }
};

// API functions
const api = {
    async fetchAgents() {
        try {
            const response = await fetch('/api/agents');
            return utils.handleResponse(response);
        } catch (error) {
            console.error('Error fetching agents:', error);
            utils.showNotification('Error fetching agents. Please try again.', 'error');
            return [];
        }
    },

    async selectAgent(agentId) {
        try {
            const response = await fetch(`/select_agent/${agentId}`, { method: 'POST' });
            return utils.handleResponse(response);
        } catch (error) {
            console.error('Error selecting agent:', error);
            utils.showNotification(`Error selecting agent: ${error.message}`, 'error');
            throw error;
        }
    },

    async fetchProcesses() {
        try {
            const response = await fetch('/api/processes');
            return utils.handleResponse(response);
        } catch (error) {
            console.error('Error fetching processes:', error);
            utils.showNotification('Error fetching processes. Please try again.', 'error');
            throw error;
        }
    },

    async fetchServices() {
        try {
            const response = await fetch('/api/services');
            return utils.handleResponse(response);
        } catch (error) {
            console.error('Error fetching services:', error);
            utils.showNotification('Error fetching services. Please try again.', 'error');
            throw error;
        }
    },

    async fetchFirewallRules() {
        try {
            const response = await fetch('/api/firewall_rules');
            return utils.handleResponse(response);
        } catch (error) {
            console.error('Error fetching firewall rules:', error);
            utils.showNotification('Error fetching firewall rules. Please try again.', 'error');
            throw error;
        }
    },

    async addFirewallRule(rule) {
        try {
            const response = await fetch('/api/firewall_rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(rule),
            });
            return utils.handleResponse(response);
        } catch (error) {
            console.error('Error adding firewall rule:', error);
            utils.showNotification('Error adding firewall rule. Please try again.', 'error');
            throw error;
        }
    },

    async removeFirewallRule(ruleId) {
        try {
            const response = await fetch(`/api/firewall_rules?id=${ruleId}`, { method: 'DELETE' });
            return utils.handleResponse(response);
        } catch (error) {
            console.error('Error removing firewall rule:', error);
            utils.showNotification('Error removing firewall rule. Please try again.', 'error');
            throw error;
        }
    }
};

// Main application logic
document.addEventListener('DOMContentLoaded', function() {
    const elements = {
        agentSelect: document.getElementById('agent-select'),
        processesTable: document.getElementById('processes-table'),
        servicesTable: document.getElementById('services-table'),
        firewallTable: document.getElementById('firewall-table'),
        addRuleModal: document.getElementById('add-rule-modal'),
        addRuleForm: document.getElementById('add-rule-form'),
        searchInput: document.getElementById('service-search'),
        categoryFilter: document.getElementById('category-filter'),
        prevPageBtn: document.getElementById('prev-page'),
        nextPageBtn: document.getElementById('next-page'),
        currentPageSpan: document.getElementById('current-page'),
        totalPagesSpan: document.getElementById('total-pages')
    };

    let selectedAgentId = null;
    let services = [];
    let currentPage = 1;
    const itemsPerPage = 20;

    function initializeApp() {
        updateClock();
        setInterval(updateClock, 1000);

        if (document.getElementById('dashboard-counts')) {
            updateDashboardCounts();
            setInterval(updateDashboardCounts, 5000);
        }

        if (document.getElementById('system-load-chart')) {
            createSystemLoadChart();
        }

        if (elements.agentSelect) {
            api.fetchAgents().then(populateAgentSelect);
        }

        setupEventListeners();
    }

    function setupEventListeners() {
        elements.agentSelect?.addEventListener('change', handleAgentSelection);
        document.getElementById('add-agent-btn')?.addEventListener('click', () => utils.toggleModal(elements.addRuleModal, true));
        document.getElementById('add-agent-form')?.addEventListener('submit', handleAddAgent);
        elements.addRuleForm?.addEventListener('submit', handleAddFirewallRule);
        elements.searchInput?.addEventListener('input', handleServiceSearch);
        elements.categoryFilter?.addEventListener('change', handleServiceSearch);
        elements.prevPageBtn?.addEventListener('click', () => changePage(-1));
        elements.nextPageBtn?.addEventListener('click', () => changePage(1));
    }

    function updateClock() {
        const now = new Date();
        document.getElementById('current-time').textContent = `${now.toLocaleDateString()} ${now.toLocaleTimeString()}`;
    }

    function updateDashboardCounts() {
        const endpoints = {
            'agent-count': '/api/agents',
            'process-count': '/api/processes',
            'user-count': '/api/users',
            'app-count': '/api/applications'
        };

        Object.entries(endpoints).forEach(([elementId, endpoint]) => {
            fetch(endpoint)
                .then(utils.handleResponse)
                .then(data => {
                    document.getElementById(elementId).querySelector('.large-number').textContent = data.length;
                })
                .catch(error => console.error(`Error updating ${elementId}:`, error));
        });
    }

    function createSystemLoadChart() {
        const ctx = document.getElementById('system-load-chart')?.getContext('2d');
        if (!ctx) return;

        new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['1m', '5m', '15m', '30m', '1h', '2h'],
                datasets: [{
                    label: 'CPU Load',
                    data: [65, 59, 80, 81, 56, 55],
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: { y: { beginAtZero: true } }
            }
        });
    }

    function populateAgentSelect(agents) {
        if (!elements.agentSelect) return;
        elements.agentSelect.innerHTML = '<option value="">Select an agent</option>' +
            agents.map(agent => `<option value="${agent.id}">${utils.escapeHtml(agent.name)} (${utils.escapeHtml(agent.ip_address)})</option>`).join('');
    }

    async function handleAgentSelection() {
        const agentId = elements.agentSelect.value;
        if (!agentId) return;

        try {
            await api.selectAgent(agentId);
            selectedAgentId = agentId;
            utils.showNotification('Agent selected successfully', 'success');
            loadDataForSelectedAgent();
        } catch (error) {
            console.error('Error selecting agent:', error);
            utils.showNotification(`Error selecting agent: ${error.message}`, 'error');
        }
    }

    function loadDataForSelectedAgent() {
        if (elements.processesTable) loadProcesses();
        if (elements.servicesTable) loadServices();
        if (elements.firewallTable) loadFirewallRules();
    }

    async function loadProcesses() {
        if (!selectedAgentId) {
            utils.showNotification('Please select an agent first', 'warning');
            return;
        }

        try {
            const processes = await api.fetchProcesses();
            updateProcessesTable(processes);
        } catch (error) {
            console.error('Error loading processes:', error);
            utils.showNotification('Error loading processes. Please try again.', 'error');
        }
    }

    function updateProcessesTable(processes) {
        const tableBody = elements.processesTable.querySelector('tbody');
        tableBody.innerHTML = '';
        processes.forEach(process => {
            const row = tableBody.insertRow();
            row.innerHTML = `
                <td>${utils.escapeHtml(process.pid)}</td>
                <td>${utils.escapeHtml(process.name)}</td>
                <td>${utils.escapeHtml(process.username)}</td>
                <td>${process.cpu_percent ? process.cpu_percent.toFixed(2) : 'N/A'}</td>
                <td>${process.memory_percent ? process.memory_percent.toFixed(2) : 'N/A'}</td>
            `;
        });
    }

    async function loadServices() {
        if (!selectedAgentId) {
            utils.showNotification('Please select an agent first', 'warning');
            return;
        }

        try {
            const data = await api.fetchServices();
            services = data.services;
            updateServicesTable();
            populateCategoryFilter(services);
        } catch (error) {
            console.error('Error loading services:', error);
            utils.showNotification('Error loading services. Please try again.', 'error');
        }
    }

    function updateServicesTable() {
        const filteredServices = filterServices();
        const totalPages = Math.ceil(filteredServices.length / itemsPerPage);
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const servicesToShow = filteredServices.slice(startIndex, endIndex);

        const tableBody = elements.servicesTable.querySelector('tbody');
        tableBody.innerHTML = '';
        servicesToShow.forEach(service => {
            const row = tableBody.insertRow();
            row.innerHTML = `
                <td>${utils.escapeHtml(service.name)}</td>
                <td>${utils.escapeHtml(service.category)}</td>
            `;
            row.addEventListener('click', () => showServiceDetails(service));
        });

        updatePagination(totalPages);
    }

    function updatePagination(totalPages) {
        elements.currentPageSpan.textContent = currentPage;
        elements.totalPagesSpan.textContent = totalPages;
        elements.prevPageBtn.disabled = currentPage === 1;
        elements.nextPageBtn.disabled = currentPage === totalPages;
    }

    function filterServices() {
        const searchTerm = elements.searchInput.value.toLowerCase();
        const selectedCategory = elements.categoryFilter.value;
        return services.filter(service => {
            const nameMatch = service.name.toLowerCase().includes(searchTerm);
            const categoryMatch = !selectedCategory || service.category === selectedCategory;
            return nameMatch && categoryMatch;
        });
    }

    function populateCategoryFilter(services) {
        const categories = [...new Set(services.map(service => service.category))];
        elements.categoryFilter.innerHTML = '<option value="">All Categories</option>' +
            categories.map(category => `<option value="${utils.escapeHtml(category)}">${utils.escapeHtml(category)}</option>`).join('');
    }

    function showServiceDetails(service) {
        const modal = document.getElementById('service-modal');
        const messageElement = document.getElementById('service-message');
        messageElement.innerHTML = `
            <strong>Name:</strong> ${utils.escapeHtml(service.name)}<br>
            <strong>Category:</strong> ${utils.escapeHtml(service.category)}
        `;
        utils.toggleModal(modal, true);
    }

    function handleServiceSearch() {
        currentPage = 1;
        updateServicesTable();
    }

    function changePage(delta) {
        const filteredServices = filterServices();
        const totalPages = Math.ceil(filteredServices.length / itemsPerPage);
        currentPage = Math.max(1, Math.min(currentPage + delta, totalPages));
        updateServicesTable();
    }

    async function loadFirewallRules() {
        try {
            const rules = await api.fetchFirewallRules();
            updateFirewallTable(rules);
        } catch (error) {
            console.error('Error loading firewall rules:', error);
            utils.showNotification('Error loading firewall rules. Please try again.', 'error');
        }
    }

    function updateFirewallTable(rules) {
        const tableBody = elements.firewallTable.querySelector('tbody');
        tableBody.innerHTML = '';
        rules.forEach(rule => {
            const row = tableBody.insertRow();
            row.innerHTML = `
                <td>${utils.escapeHtml(rule.protocol)}</td>
                <td>${utils.escapeHtml(rule.destination_port)}</td>
                <td>${utils.escapeHtml(rule.action)}</td>
                <td>${utils.escapeHtml(rule.source || 'Any')}</td>
                <td>${utils.escapeHtml(rule.destination || 'Any')}</td>
                <td>
                    <button class="btn btn-small btn-danger remove-rule-btn" data-rule-id="${rule.id}">Remove</button>
                </td>
            `;
            row.querySelector('.remove-rule-btn').addEventListener('click', () => removeFirewallRule(rule.id));
        });
    }

    async function handleAddFirewallRule(e) {
        e.preventDefault();
        const rule = {
            protocol: document.getElementById('rule-protocol').value,
            destination_port: document.getElementById('rule-destination-port').value,
            action: document.getElementById('rule-action').value,
            source: document.getElementById('rule-source').value || null,
            destination: document.getElementById('rule-destination').value || null
        };

        try {
            await api.addFirewallRule(rule);
            utils.showNotification('Firewall rule added successfully', 'success');
            utils.toggleModal(elements.addRuleModal, false);
            elements.addRuleForm.reset();
            await loadFirewallRules();
        } catch (error) {
            console.error('Error adding firewall rule:', error);
            utils.showNotification('Failed to add firewall rule. Please try again.', 'error');
        }
    }

    async function removeFirewallRule(ruleId) {
        if (confirm('Are you sure you want to remove this firewall rule?')) {
            try {
                await api.removeFirewallRule(ruleId);
                utils.showNotification('Firewall rule removed successfully', 'success');
                await loadFirewallRules();
            } catch (error) {
                console.error('Error removing firewall rule:', error);
                utils.showNotification('Failed to remove firewall rule. Please try again.', 'error');
            }
        }
    }

    async function handleAddAgent(e) {
        e.preventDefault();
        const name = document.getElementById('agent-name').value;
        const ipAddress = document.getElementById('agent-ip').value;
        if (name && ipAddress) {
            try {
                const response = await fetch('/api/agents', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, ip_address: ipAddress }),
                });
                const data = await utils.handleResponse(response);
                utils.showNotification(data.message, 'success');
                utils.toggleModal(document.getElementById('add-agent-modal'), false);
                await api.fetchAgents().then(populateAgentSelect);
            } catch (error) {
                console.error('Error adding agent:', error);
                utils.showNotification('Failed to add agent. Please try again.', 'error');
            }
        } else {
            utils.showNotification('Please fill in all fields', 'error');
        }
    }

    function initializeTooltips() {
        const tooltips = document.querySelectorAll('[data-tooltip]');
        tooltips.forEach(element => {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = element.getAttribute('data-tooltip');
            element.appendChild(tooltip);
        });
    }

    // Event delegation for dynamic elements
    document.body.addEventListener('click', function(e) {
        if (e.target.classList.contains('close-modal')) {
            const modal = e.target.closest('.modal');
            if (modal) utils.toggleModal(modal, false);
        }
    });

    // Initialize the application
    initializeApp();
    initializeTooltips();
});
