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