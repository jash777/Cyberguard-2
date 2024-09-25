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