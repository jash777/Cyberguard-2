document.addEventListener('DOMContentLoaded', function() {
    const agentSelect = document.getElementById('agent-select');
    const processesTable = document.getElementById('processes-table')?.getElementsByTagName('tbody')[0];
    const refreshInterval = 5000; // Refresh every 5 seconds
    let selectedAgentId = null;
    var flashMessages = document.querySelectorAll('.flash-message');
    
    flashMessages.forEach(function(message) {
        message.addEventListener('click', function() {
            this.style.display = 'none';
        });

        // Auto-dismiss after 5 seconds
        setTimeout(function() {
            message.style.opacity = '0';
            setTimeout(function() {
                message.style.display = 'none';
            }, 300);
        }, 5000);
    });

    function showAlert(message, type = 'error') {
        const alertContainer = document.getElementById('alert-container');
        const alertElement = document.createElement('div');
        alertElement.className = `alert alert-${type}`;
        alertElement.textContent = message;
        alertContainer.appendChild(alertElement);
    
        // Remove the alert after 5 seconds
        setTimeout(() => {
            alertElement.remove();
        }, 5000);
    }
    
    document.addEventListener('DOMContentLoaded', () => {
        // Check for error parameter in URL
        const urlParams = new URLSearchParams(window.location.search);
        const errorMessage = urlParams.get('error');
        if (errorMessage) {
            showAlert(errorMessage);
            // Remove the error parameter from the URL
            urlParams.delete('error');
            const newUrl = window.location.pathname + (urlParams.toString() ? '?' + urlParams.toString() : '');
            window.history.replaceState({}, '', newUrl);
        }
    });
    // Initialize components based on the current page
    updateClock();
    setInterval(updateClock, 1000);

    if (document.getElementById('dashboard-counts')) {
        updateDashboardCounts();
        setInterval(updateDashboardCounts, refreshInterval);
    }

    if (document.getElementById('system-load-chart')) {
        createSystemLoadChart();
    }

    if (agentSelect) {
        fetchAgents();
        agentSelect.addEventListener('change', handleAgentSelection);
    }

    if (processesTable) {
        setInterval(() => {
            if (selectedAgentId) {
                fetchProcesses();
            }
        }, refreshInterval);
    }

    function updateClock() {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        const dateString = now.toLocaleDateString();
        document.getElementById('current-time').textContent = `${dateString} ${timeString}`;
    }

});

document.addEventListener('DOMContentLoaded', function() {
    const addAgentBtn = document.getElementById('add-agent-btn');
    const addAgentModal = document.getElementById('add-agent-modal');
    const addAgentForm = document.getElementById('add-agent-form');
    const selectedAgentName = document.getElementById('selected-agent-name');
    const agentsTable = document.getElementById('agents-table');
    const closeBtn = addAgentModal.querySelector('.close');

    addAgentBtn?.addEventListener('click', () => toggleModal(addAgentModal, true));
    closeBtn?.addEventListener('click', () => toggleModal(addAgentModal, false));
    addAgentForm?.addEventListener('submit', handleAddAgent);
    agentsTable?.addEventListener('click', handleTableActions);

    window.onclick = (event) => {
        if (event.target == addAgentModal) {
            toggleModal(addAgentModal, false);
        }
    };

    fetchSelectedAgent();
    initializeTooltips();
});

function handleAddAgent(e) {
    e.preventDefault();
    const name = document.getElementById('agent-name')?.value;
    const ipAddress = document.getElementById('agent-ip')?.value;
    if (name && ipAddress) {
        addAgent(name, ipAddress);
    } else {
        showNotification('Please fill in all fields', 'error');
    }
}

function handleTableActions(e) {
    const target = e.target;
    if (target.tagName === 'BUTTON') {
        const action = target.dataset.action;
        const agentId = target.dataset.agentId;
        if (agentId) {
            switch (action) {
                case 'remove':
                    removeAgent(agentId);
                    break;
                case 'check-status':
                    checkAgentStatus(agentId);
                    break;
                case 'select':
                    selectAgent(agentId);
                    break;
                default:
                    console.warn(`Unknown action: ${action}`);
            }
        } else {
            console.error('Agent ID not found');
        }
    }
}

function addAgent(name, ipAddress) {
    fetch('/api/agents', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, ip_address: ipAddress }),
    })
    .then(handleResponse)
    .then(data => {
        showNotification(data.message, 'success');
        location.reload();
    })
    .catch(error => showError('Error adding agent:', error));
}

function removeAgent(agentId) {
    if (confirm('Are you sure you want to remove this agent?')) {
        fetch(`/api/agents?id=${agentId}`, { method: 'DELETE' })
        .then(handleResponse)
        .then(data => {
            showNotification(data.message, 'success');
            location.reload();
        })
        .catch(error => showError('Error removing agent:', error));
    }
}

function checkAgentStatus(agentId) {
    fetch(`/api/check_agent_status/${agentId}`)
    .then(handleResponse)
    .then(data => {
        const statusCell = document.querySelector(`.agent-status[data-agent-id="${agentId}"]`);
        if (statusCell) {
            statusCell.textContent = data.status;
            statusCell.classList.add('status-updated');
            setTimeout(() => statusCell.classList.remove('status-updated'), 3000);
        }
        showNotification(`Agent status updated: ${data.status}`, 'info');
    })
    .catch(error => showError('Error checking agent status:', error));
}

function selectAgent(agentId) {
    fetch(`/select_agent/${agentId}`, { method: 'POST' })
    .then(handleResponse)
    .then(data => {
        showNotification('Agent selected successfully', 'success');
        fetchSelectedAgent();
    })
    .catch(error => showError('Error selecting agent:', error));
}

function fetchSelectedAgent() {
    fetch('/api/selected_agent')
    .then(handleResponse)
    .then(data => {
        const selectedAgentNameElement = document.getElementById('selected-agent-name');
        if (selectedAgentNameElement) {
            selectedAgentNameElement.textContent = data.selected_agent ? data.selected_agent.name : 'None';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        const selectedAgentNameElement = document.getElementById('selected-agent-name');
        if (selectedAgentNameElement) {
            selectedAgentNameElement.textContent = 'Error fetching selected agent';
        }
    });
}

function handleResponse(response) {
    if (!response.ok) {
        return response.json().then(err => { throw new Error(err.message || `HTTP error! status: ${response.status}`); });
    }
    return response.json();
}

function showError(message, error) {
    console.error(message, error);
    showNotification(`${message} ${error.message || 'Unknown error'}`, 'error');
}

function showNotification(message, type) {
    const notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) {
        console.error('Notification container not found');
        alert(`${type.toUpperCase()}: ${message}`);
        return;
    }

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    const closeBtn = document.createElement('button');
    closeBtn.className = 'close-notification';
    closeBtn.innerHTML = '&times;';
    closeBtn.onclick = () => notification.remove();

    notification.appendChild(closeBtn);
    notificationContainer.appendChild(notification);

    setTimeout(() => notification.remove(), 5000);
}

function toggleModal(modal, show) {
    if (modal) {
        modal.style.display = show ? 'block' : 'none';
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


document.addEventListener('DOMContentLoaded', function() {
    updateDashboardCounts();
    createSystemLoadChart();
});

function updateDashboardCounts() {
    const countElements = {
        'agent-count': '/api/agents',
        'process-count': '/api/processes',
        'user-count': '/api/users',
        'app-count': '/api/applications'
    };

    Object.entries(countElements).forEach(([elementId, endpoint]) => {
        const element = document.getElementById(elementId);
        if (element) {
            fetch(endpoint)
                .then(handleResponse)
                .then(data => {
                    element.querySelector('.large-number').textContent = data.length;
                })
                .catch(error => showError(`Error updating ${elementId}:`, error));
        }
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
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function handleResponse(response) {
    if (!response.ok) {
        return response.json().then(err => { throw err; });
    }
    return response.json();
}

function showError(message, error) {
    console.error(message, error);
    showAlert(`${message} ${error.message || 'Unknown error'}`);
}

document.addEventListener('DOMContentLoaded', function() {
    loadFirewallRules();

    const addRuleBtn = document.getElementById('add-rule-btn');
    const addRuleModal = document.getElementById('add-rule-modal');
    const addRuleForm = document.getElementById('add-rule-form');

    addRuleBtn.addEventListener('click', () => {
        addRuleModal.style.display = 'block';
    });

    addRuleForm.addEventListener('submit', (e) => {
        e.preventDefault();
        addFirewallRule();
    });

    window.onclick = (event) => {
        if (event.target == addRuleModal) {
            addRuleModal.style.display = 'none';
        }
    };
});

function loadFirewallRules() {
    fetch('/api/firewall_rules')
        .then(response => response.json())
        .then(rules => {
            console.log('Fetched rules:', rules); // Debugging statement
            const tableBody = document.querySelector('#firewall-table tbody');
            tableBody.innerHTML = '';
            rules.forEach(rule => {
                const row = createRuleRow(rule);
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading firewall rules:', error));
}


function createRuleRow(rule) {
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${rule.protocol}</td>
        <td>${rule.destination_port}</td>
        <td>${rule.action}</td>
        <td>${rule.source || 'Any'}</td>
        <td>${rule.destination || 'Any'}</td>
        <td>
            <button class="btn btn-small btn-danger remove-rule-btn" data-rule-id="${rule.id}">Remove</button>
        </td>
    `;

    // Attach event listener for the remove button
    row.querySelector('.remove-rule-btn').addEventListener('click', function() {
        const ruleId = this.getAttribute('data-rule-id');
        removeFirewallRule(ruleId);
    });

    return row;
}

function addFirewallRule() {
    const protocol = document.getElementById('rule-protocol').value;
    const port = document.getElementById('rule-destination-port').value;
    const action = document.getElementById('rule-action').value;
    const source = document.getElementById('rule-source').value || null;
    const destination = document.getElementById('rule-destination').value || null;

    const rule = {
        protocol: protocol,
        destination_port: port,
        action: action,
        source: source,
        destination: destination
    };

    fetch('/api/firewall_rules', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(rule),
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'completed' && data.results[0].success) {
            alert('Firewall rule added successfully');
            loadFirewallRules();
            document.getElementById('add-rule-modal').style.display = 'none';
            document.getElementById('add-rule-form').reset();
        } else {
            alert('Failed to add firewall rule');
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error adding firewall rule');
    });
}

function removeFirewallRule(ruleId) {
    if (confirm('Are you sure you want to remove this firewall rule?')) {
        fetch(`/api/firewall_rules?id=${ruleId}`, {
            method: 'DELETE',
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            loadFirewallRules();
        })
        .catch((error) => {
            console.error('Error:', error);
            alert('Error removing firewall rule');
        });
    }
}

function blockPort() {
    const port = document.getElementById('block-port-input').value;

    fetch('/api/block_port', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ port: port }),
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        loadFirewallRules();
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error blocking port');
    });
}


document.addEventListener('DOMContentLoaded', function() {
    const agentSelect = document.getElementById('agent-select');
    const processesTable = document.getElementById('processes-table');
    const processesTableBody = processesTable?.getElementsByTagName('tbody')[0];
    const selectAgentBtn = document.getElementById('select-agent-btn');
    const refreshDataBtn = document.getElementById('refresh-data-btn');
    let selectedAgentId = null;
    let isLoading = false;

    function fetchAgents() {
        fetch('/api/agents')
            .then(handleResponse)
            .then(agents => {
                if (agentSelect) {
                    agentSelect.innerHTML = '<option value="">Select an agent</option>';
                    agents.forEach(agent => {
                        const option = document.createElement('option');
                        option.value = agent.id;
                        option.textContent = `${agent.name} (${agent.ip_address})`;
                        agentSelect.appendChild(option);
                    });
                }
                checkSelectedAgent();
            })
            .catch(error => {
                console.error('Error fetching agents:', error);
                showAlert('Error fetching agents. Please try again.', 'error');
            });
    }

    function checkSelectedAgent() {
        fetch('/api/selected_agent')
            .then(handleResponse)
            .then(data => {
                if (data.selected_agent) {
                    selectedAgentId = data.selected_agent.id;
                    agentSelect.value = selectedAgentId;
                    fetchProcesses();
                } else {
                    showAlert('No agent selected. Please select an agent to view processes.', 'warning');
                }
            })
            .catch(error => {
                console.error('Error checking selected agent:', error);
                showAlert('Error checking selected agent. Please try selecting an agent manually.', 'error');
            });
    }

    function selectAgent(agentId) {
        fetch(`/select_agent/${agentId}`, { method: 'POST' })
            .then(handleResponse)
            .then(data => {
                console.log('Agent selected successfully:', data);
                selectedAgentId = agentId;
                showAlert('Agent selected successfully. Fetching processes...', 'success');
                fetchProcesses();
            })
            .catch(error => {
                console.error('Error selecting agent:', error);
                showAlert(`Error selecting agent: ${error.message || 'Unknown error'}`, 'error');
                resetAgentSelection();
            });
    }

    function fetchProcesses() {
        if (!selectedAgentId) {
            showAlert('Please select an agent first.', 'warning');
            return;
        }
    
        if (isLoading) return;
        isLoading = true;
    
        fetch('/api/processes')
            .then(handleResponse)
            .then(processes => {
                if (Array.isArray(processes)) {
                    updateProcessesTable(processes);
                    showAlert('Processes fetched successfully.', 'success');
                } else {
                    throw new Error('Unexpected data format received');
                }
            })
            .catch(error => {
                console.error('Error fetching processes:', error);
                showAlert(`Error fetching processes: ${error.message}. Please try again.`, 'error');
                clearProcessesTable();
            })
            .finally(() => {
                isLoading = false;
            });
    }

    function updateProcessesTable(processes) {
        if (!processesTableBody) return;
        clearProcessesTable();
        if (processes.length === 0) {
            showAlert('No processes found for this agent.', 'info');
            return;
        }

        const fragment = document.createDocumentFragment();
        processes.forEach((process) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${escapeHtml(process.pid)}</td>
                <td>${escapeHtml(process.name)}</td>
                <td>${escapeHtml(process.username)}</td>
                <td>${process.cpu_percent ? process.cpu_percent.toFixed(2) : 'N/A'}</td>
                <td>${process.memory_percent ? process.memory_percent.toFixed(2) : 'N/A'}</td>
            `;
            fragment.appendChild(row);
        });
        processesTableBody.appendChild(fragment);
    }

    function clearProcessesTable() {
        if (processesTableBody) {
            processesTableBody.innerHTML = '';
        }
    }

    function showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alert-container');
        if (!alertContainer) {
            console.error('Alert container not found');
            alert(`${type.toUpperCase()}: ${message}`);
            return;
        }

        const alertElement = document.createElement('div');
        alertElement.className = `alert alert-${type}`;
        alertElement.textContent = message;

        const closeButton = document.createElement('button');
        closeButton.className = 'close-alert';
        closeButton.innerHTML = '&times;';
        closeButton.onclick = () => alertElement.remove();

        alertElement.appendChild(closeButton);
        alertContainer.appendChild(alertElement);

        setTimeout(() => alertElement.remove(), 5000); // Auto-remove after 5 seconds
    }

    function resetAgentSelection() {
        selectedAgentId = null;
        if (agentSelect) {
            agentSelect.value = '';
        }
        clearProcessesTable();
    }

    function escapeHtml(unsafe) {
        if (unsafe == null) return '';
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function handleResponse(response) {
        return response.json().then(data => {
            if (!response.ok) {
                const error = (data && data.error) || response.statusText;
                return Promise.reject(error);
            }
            return data;
        });
    }

    selectAgentBtn?.addEventListener('click', function() {
        const agentId = agentSelect?.value;
        if (agentId) {
            selectAgent(agentId);
        } else {
            showAlert('Please select an agent', 'warning');
        }
    });

    refreshDataBtn?.addEventListener('click', function() {
        if (selectedAgentId) {
            fetchProcesses();
        } else {
            showAlert('Please select an agent first', 'warning');
        }
    });

    // Initial fetch of agents and check for selected agent
    fetchAgents();
});

document.addEventListener('DOMContentLoaded', function() {
    const agentSelect = document.getElementById('agent-select');
    const servicesTable = document.getElementById('services-table');
    const servicesTableBody = servicesTable.querySelector('tbody');
    const selectAgentBtn = document.getElementById('select-agent-btn');
    const refreshDataBtn = document.getElementById('refresh-data-btn');
    const searchInput = document.getElementById('service-search');
    const categoryFilter = document.getElementById('category-filter');
    const selectedAgentNameSpan = document.getElementById('selected-agent-name');
    const serviceModal = document.getElementById('service-modal');
    const serviceMessage = document.getElementById('service-message');
    const prevPageBtn = document.getElementById('prev-page');
    const nextPageBtn = document.getElementById('next-page');
    const currentPageSpan = document.getElementById('current-page');
    const totalPagesSpan = document.getElementById('total-pages');

    let selectedAgentId = null;
    let services = [];
    let currentPage = 1;
    const itemsPerPage = 20;

    function fetchAgents() {
        fetch('/api/agents')
            .then(response => response.json())
            .then(agents => {
                const fragment = document.createDocumentFragment();
                fragment.appendChild(new Option('Select an agent', ''));
                agents.forEach(agent => {
                    fragment.appendChild(new Option(`${agent.name} (${agent.ip_address})`, agent.id));
                });
                agentSelect.innerHTML = '';
                agentSelect.appendChild(fragment);
            })
            .catch(error => {
                console.error('Error fetching agents:', error);
                showAlert('Error fetching agents. Please try again.');
            });
    }

    function selectAgent(agentId) {
        fetch(`/select_agent/${agentId}`, { method: 'POST' })
            .then(response => {
                if (!response.ok) throw new Error('Failed to select agent');
                return response.json();
            })
            .then(data => {
                console.log('Agent selected successfully:', data);
                selectedAgentId = agentId;
                selectedAgentNameSpan.textContent = data.agent;
                loadServices();
            })
            .catch(error => {
                console.error('Error selecting agent:', error);
                showAlert(`Error selecting agent: ${error.message || 'Unknown error'}`);
                resetAgentSelection();
            });
    }

    function loadServices() {
        if (!selectedAgentId) {
            showAlert('Please select an agent first.');
            return;
        }

        fetch('/api/services')
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch services');
                return response.json();
            })
            .then(data => {
                if (data.error) throw new Error(data.error);
                services = data.services;
                currentPage = 1;
                updateServicesTable();
                populateCategoryFilter(services);
            })
            .catch(error => {
                console.error('Error fetching services:', error);
                showAlert(`Error fetching services: ${error.message}. Please select an agent again.`);
                resetAgentSelection();
            });
    }

    function updateServicesTable() {
        clearServicesTable();
        const filteredServices = filterServices();
        const totalPages = Math.ceil(filteredServices.length / itemsPerPage);
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const servicesToShow = filteredServices.slice(startIndex, endIndex);

        if (servicesToShow.length === 0) {
            showAlert('No services found for this agent.');
            return;
        }

        const fragment = document.createDocumentFragment();
        servicesToShow.forEach((service) => {
            const row = fragment.appendChild(document.createElement('tr'));
            row.innerHTML = `
                <td>${escapeHtml(service.name)}</td>
                <td>${escapeHtml(service.category)}</td>
            `;
            row.addEventListener('click', () => showServiceDetails(service));
        });
        servicesTableBody.appendChild(fragment);

        updatePagination(totalPages);
    }

    function updatePagination(totalPages) {
        currentPageSpan.textContent = currentPage;
        totalPagesSpan.textContent = totalPages;
        prevPageBtn.disabled = currentPage === 1;
        nextPageBtn.disabled = currentPage === totalPages;
    }

    function populateCategoryFilter(services) {
        const categories = [...new Set(services.map(service => service.category))];
        const fragment = document.createDocumentFragment();
        fragment.appendChild(new Option('All Categories', ''));
        categories.forEach(category => {
            fragment.appendChild(new Option(category, category));
        });
        categoryFilter.innerHTML = '';
        categoryFilter.appendChild(fragment);
    }

    function clearServicesTable() {
        servicesTableBody.innerHTML = '';
    }

    function showAlert(message) {
        clearServicesTable();
        const alertRow = servicesTableBody.insertRow();
        alertRow.innerHTML = `<td colspan="2" class="alert-message">${escapeHtml(message)}</td>`;
    }

    function resetAgentSelection() {
        selectedAgentId = null;
        agentSelect.value = '';
        selectedAgentNameSpan.textContent = 'None';
        clearServicesTable();
        categoryFilter.innerHTML = '<option value="">All Categories</option>';
        currentPage = 1;
        updatePagination(1);
    }

    const escapeHtml = (function() {
        const entityMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;'
        };
        return function(string) {
            return String(string).replace(/[&<>"'`=\/]/g, function(s) {
                return entityMap[s];
            });
        };
    })();

    function showServiceDetails(service) {
        serviceMessage.innerHTML = `
            <strong>Name:</strong> ${escapeHtml(service.name)}<br>
            <strong>Category:</strong> ${escapeHtml(service.category)}
        `;
        serviceModal.style.display = 'block';
    }

    function closeServiceModal() {
        serviceModal.style.display = 'none';
    }

    function filterServices() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedCategory = categoryFilter.value;
        return services.filter(service => {
            const nameMatch = service.name.toLowerCase().includes(searchTerm);
            const categoryMatch = !selectedCategory || service.category === selectedCategory;
            return nameMatch && categoryMatch;
        });
    }

    selectAgentBtn.addEventListener('click', () => {
        const agentId = agentSelect.value;
        agentId ? selectAgent(agentId) : showAlert('Please select an agent');
    });

    refreshDataBtn.addEventListener('click', () => {
        selectedAgentId ? loadServices() : showAlert('Please select an agent first');
    });

    searchInput.addEventListener('input', () => {
        currentPage = 1;
        updateServicesTable();
    });

    categoryFilter.addEventListener('change', () => {
        currentPage = 1;
        updateServicesTable();
    });

    prevPageBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            updateServicesTable();
        }
    });

    nextPageBtn.addEventListener('click', () => {
        const filteredServices = filterServices();
        const totalPages = Math.ceil(filteredServices.length / itemsPerPage);
        if (currentPage < totalPages) {
            currentPage++;
            updateServicesTable();
        }
    });

    document.getElementById('close-service-modal').addEventListener('click', closeServiceModal);

    // Initial fetch of agents
    fetchAgents();
});
