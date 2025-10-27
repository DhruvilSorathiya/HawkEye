/**
 * HawkEye Admin Dashboard JavaScript
 */

$(document).ready(function() {
    // Initialize data tables
    $('#usersTable').DataTable({
        "pageLength": 10,
        "order": [[ 4, "desc" ]],
        "columnDefs": [
            { "orderable": false, "targets": 6 }
        ]
    });
    
    // Load recent activity
    loadRecentActivity();
    
    // Auto-refresh every 30 seconds
    setInterval(function() {
        loadRecentActivity();
    }, 30000);
});

function showCreateUserModal() {
    $('#createUserModal').modal('show');
}

function showCreateAdminModal() {
    $('#createAdminModal').modal('show');
}

function createUser() {
    var formData = {
        username: $('#newUsername').val(),
        password: $('#newPassword').val(),
        email: $('#newEmail').val(),
        mobile: $('#newMobile').val()
    };
    
    if (!formData.username || !formData.password || !formData.email) {
        alertify.error('Please fill in all required fields');
        return;
    }
    
    $.ajax({
        url: docroot + '/admin_create_user',
        method: 'POST',
        data: formData,
        success: function(response) {
            if (response.success) {
                alertify.success('User created successfully');
                $('#createUserModal').modal('hide');
                $('#createUserForm')[0].reset();
                location.reload();
            } else {
                alertify.error(response.message || 'Failed to create user');
            }
        },
        error: function() {
            alertify.error('An error occurred while creating the user');
        }
    });
}

function createAdmin() {
    var formData = {
        username: $('#adminUsername').val(),
        password: $('#adminPassword').val(),
        email: $('#adminEmail').val(),
        mobile: $('#adminMobile').val(),
        auth_username: $('#authAdminUsername').val(),
        auth_password: $('#authAdminPassword').val(),
        confirm_password: $('#confirmAdminPassword').val()
    };
    
    if (!formData.username || !formData.password || !formData.email || !formData.auth_username || !formData.auth_password) {
        alertify.error('Please fill in all required fields');
        return;
    }
    
    if (formData.password !== formData.confirm_password) {
        alertify.error('Passwords do not match');
        return;
    }
    
    $.ajax({
        url: docroot + '/admin_create_admin',
        method: 'POST',
        data: formData,
        success: function(response) {
            if (response.success) {
                alertify.success('Admin created successfully');
                $('#createAdminModal').modal('hide');
                $('#createAdminForm')[0].reset();
            } else {
                alertify.error(response.message || 'Failed to create admin');
            }
        },
        error: function() {
            alertify.error('An error occurred while creating the admin');
        }
    });
}

function viewUserActivity(userId, username) {
    $('#activityUserName').text(username);
    $('#userActivityBody').html('<tr><td colspan="5" class="text-center">Loading...</td></tr>');
    $('#userActivityModal').modal('show');
    
    $.ajax({
        url: docroot + '/admin_user_activity',
        data: { user_id: userId },
        method: 'GET',
        success: function(response) {
            if (response.success && response.activities) {
                var html = '';
                if (response.activities.length === 0) {
                    html = '<tr><td colspan="5" class="text-center text-muted">No activity found</td></tr>';
                } else {
                    response.activities.forEach(function(activity) {
                        var date = new Date(activity.created_at * 1000).toLocaleString();
                        html += '<tr>';
                        html += '<td><span class="label label-info">' + activity.activity_type + '</span></td>';
                        html += '<td>' + activity.activity_description + '</td>';
                        html += '<td>' + (activity.scan_id || 'N/A') + '</td>';
                        html += '<td>' + date + '</td>';
                        html += '<td>' + (activity.ip_address || 'N/A') + '</td>';
                        html += '</tr>';
                    });
                }
                $('#userActivityBody').html(html);
            } else {
                $('#userActivityBody').html('<tr><td colspan="5" class="text-center text-danger">Error loading activity</td></tr>');
            }
        },
        error: function() {
            $('#userActivityBody').html('<tr><td colspan="5" class="text-center text-danger">Error loading activity</td></tr>');
        }
    });
}

function toggleUserStatus(userId, currentStatus) {
    var action = currentStatus ? 'deactivate' : 'activate';
    var message = currentStatus ? 'deactivate' : 'activate';
    
    alertify.confirm('Are you sure you want to ' + message + ' this user?', function() {
        $.ajax({
            url: docroot + '/admin_toggle_user_status',
            method: 'POST',
            data: {
                user_id: userId,
                action: action
            },
            success: function(response) {
                if (response.success) {
                    alertify.success('User ' + message + 'd successfully');
                    location.reload();
                } else {
                    alertify.error(response.message || 'Failed to ' + message + ' user');
                }
            },
            error: function() {
                alertify.error('An error occurred while updating user status');
            }
        });
    });
}

function loadRecentActivity() {
    $.ajax({
        url: docroot + '/admin_recent_activity',
        method: 'GET',
        success: function(response) {
            if (response.success && response.activities) {
                var html = '';
                if (response.activities.length === 0) {
                    html = '<p class="text-muted">No recent activity</p>';
                } else {
                    response.activities.forEach(function(activity) {
                        var date = new Date(activity.created_at * 1000).toLocaleString();
                        html += '<div class="activity-item">';
                        html += '<div class="activity-type">' + activity.activity_type + '</div>';
                        html += '<div class="activity-description">' + activity.activity_description + '</div>';
                        html += '<div class="activity-time">' + date + '</div>';
                        html += '</div>';
                    });
                }
                $('#recentActivity').html(html);
            }
        },
        error: function() {
            $('#recentActivity').html('<p class="text-danger">Error loading activity</p>');
        }
    });
}

// System Settings functionality
var currentLogOffset = 0;
var currentLogLimit = 100;
var currentLogLevel = null;
var currentLogCategory = null;

function showSystemSettings() {
    $('#systemSettingsModal').modal('show');
    loadSystemSettings();
}

function loadSystemSettings() {
    $('#systemSettingsContent').html('<div class="text-center"><i class="glyphicon glyphicon-refresh glyphicon-spin"></i> Loading settings...</div>');
    
    $.ajax({
        url: docroot + '/admin_get_system_settings',
        method: 'POST',
        dataType: 'json',
        success: function(response) {
            if (response.success && response.settings) {
                var html = '<div class="list-group">';
                response.settings.forEach(function(setting) {
                    var inputType = 'text';
                    var inputClass = 'form-control';
                    var inputHtml = '';
                    
                    if (setting.type === 'boolean') {
                        inputHtml = '<select class="form-control setting-input" data-key="' + setting.key + '">' +
                            '<option value="true"' + (setting.value === 'true' ? ' selected' : '') + '>Enabled</option>' +
                            '<option value="false"' + (setting.value === 'false' ? ' selected' : '') + '>Disabled</option>' +
                            '</select>';
                    } else if (setting.type === 'integer') {
                        inputHtml = '<input type="number" class="form-control setting-input" data-key="' + setting.key + '" value="' + setting.value + '">';
                    } else {
                        inputHtml = '<input type="text" class="form-control setting-input" data-key="' + setting.key + '" value="' + setting.value + '">';
                    }
                    
                    var updatedText = '';
                    if (setting.updated_at) {
                        var updatedDate = new Date(setting.updated_at * 1000).toLocaleString();
                        updatedText = '<small class="text-muted">Last updated: ' + updatedDate + '</small>';
                    }
                    
                    html += '<div class="list-group-item" style="border-left: 4px solid #667eea;">' +
                        '<div class="row">' +
                        '<div class="col-md-5">' +
                        '<strong>' + setting.key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) + '</strong><br>' +
                        '<small class="text-muted">' + (setting.description || '') + '</small><br>' +
                        updatedText +
                        '</div>' +
                        '<div class="col-md-5">' +
                        inputHtml +
                        '</div>' +
                        '<div class="col-md-2">' +
                        '<button class="btn btn-primary btn-sm btn-block" onclick="updateSetting(\'' + setting.key + '\')">' +
                        '<i class="glyphicon glyphicon-floppy-disk"></i> Save' +
                        '</button>' +
                        '</div>' +
                        '</div>' +
                        '</div>';
                });
                html += '</div>';
                $('#systemSettingsContent').html(html);
            } else {
                $('#systemSettingsContent').html('<div class="alert alert-danger">Error loading settings: ' + (response.message || 'Unknown error') + '</div>');
            }
        },
        error: function() {
            $('#systemSettingsContent').html('<div class="alert alert-danger">Failed to load system settings</div>');
        }
    });
}

function updateSetting(settingKey) {
    var newValue = $('.setting-input[data-key="' + settingKey + '"]').val();
    
    $.ajax({
        url: docroot + '/admin_update_system_setting',
        method: 'POST',
        data: {
            setting_key: settingKey,
            setting_value: newValue
        },
        dataType: 'json',
        success: function(response) {
            if (response.success) {
                alertify.success('Setting updated successfully');
                loadSystemSettings(); // Reload to show updated timestamp
            } else {
                alertify.error(response.message || 'Failed to update setting');
            }
        },
        error: function() {
            alertify.error('Error updating setting');
        }
    });
}

// System Logs functionality
function viewSystemLogs() {
    $('#systemLogsModal').modal('show');
    currentLogOffset = 0;
    currentLogLimit = 100;
    currentLogLevel = null;
    currentLogCategory = null;
    loadSystemLogs();
}

function loadSystemLogs() {
    $('#systemLogsBody').html('<tr><td colspan="6" class="text-center"><i class="glyphicon glyphicon-refresh glyphicon-spin"></i> Loading logs...</td></tr>');
    
    var params = {
        limit: currentLogLimit,
        offset: currentLogOffset
    };
    
    if (currentLogLevel) params.log_level = currentLogLevel;
    if (currentLogCategory) params.log_category = currentLogCategory;
    
    $.ajax({
        url: docroot + '/admin_get_system_logs',
        method: 'POST',
        data: params,
        dataType: 'json',
        success: function(response) {
            if (response.success && response.logs) {
                var html = '';
                if (response.logs.length === 0) {
                    html = '<tr><td colspan="6" class="text-center text-muted">No logs found</td></tr>';
                } else {
                    response.logs.forEach(function(log) {
                        var timestamp = new Date(log.created_at * 1000).toLocaleString();
                        var levelClass = '';
                        var levelIcon = '';
                        
                        switch(log.level) {
                            case 'INFO':
                                levelClass = 'label-info';
                                levelIcon = 'glyphicon-info-sign';
                                break;
                            case 'WARNING':
                                levelClass = 'label-warning';
                                levelIcon = 'glyphicon-warning-sign';
                                break;
                            case 'ERROR':
                                levelClass = 'label-danger';
                                levelIcon = 'glyphicon-exclamation-sign';
                                break;
                            case 'CRITICAL':
                                levelClass = 'label-danger';
                                levelIcon = 'glyphicon-fire';
                                break;
                            default:
                                levelClass = 'label-default';
                                levelIcon = 'glyphicon-record';
                        }
                        
                        var user = log.user_username || log.admin_username || '-';
                        var ip = log.ip_address || '-';
                        
                        html += '<tr>' +
                            '<td><small>' + timestamp + '</small></td>' +
                            '<td><span class="label ' + levelClass + '"><i class="glyphicon ' + levelIcon + '"></i> ' + log.level + '</span></td>' +
                            '<td><span class="label label-primary">' + log.category + '</span></td>' +
                            '<td>' + log.message + '</td>' +
                            '<td>' + user + '</td>' +
                            '<td>' + ip + '</td>' +
                            '</tr>';
                    });
                }
                $('#systemLogsBody').html(html);
                
                // Update count info
                var showing = Math.min(currentLogOffset + response.logs.length, response.total);
                $('#logCountInfo').html('<strong>Showing ' + (currentLogOffset + 1) + '-' + showing + ' of ' + response.total + ' logs</strong>');
                
                // Update pagination
                renderLogsPagination(response.total);
            } else {
                $('#systemLogsBody').html('<tr><td colspan="6" class="text-danger">Error: ' + (response.message || 'Unknown error') + '</td></tr>');
            }
        },
        error: function() {
            $('#systemLogsBody').html('<tr><td colspan="6" class="text-danger">Failed to load system logs</td></tr>');
        }
    });
}

function applyLogFilters() {
    currentLogLevel = $('#logLevelFilter').val() || null;
    currentLogCategory = $('#logCategoryFilter').val() || null;
    currentLogLimit = parseInt($('#logLimitFilter').val()) || 100;
    currentLogOffset = 0;
    loadSystemLogs();
}

function refreshSystemLogs() {
    loadSystemLogs();
}

function renderLogsPagination(totalLogs) {
    var totalPages = Math.ceil(totalLogs / currentLogLimit);
    var currentPage = Math.floor(currentLogOffset / currentLogLimit) + 1;
    
    if (totalPages <= 1) {
        $('#logsPagination').html('');
        return;
    }
    
    var html = '<ul class="pagination" style="margin: 0;">';
    
    // Previous button
    if (currentPage > 1) {
        html += '<li><a href="#" onclick="goToLogPage(' + (currentPage - 1) + '); return false;">&laquo; Previous</a></li>';
    } else {
        html += '<li class="disabled"><span>&laquo; Previous</span></li>';
    }
    
    // Page numbers (show max 5 pages)
    var startPage = Math.max(1, currentPage - 2);
    var endPage = Math.min(totalPages, startPage + 4);
    
    if (endPage - startPage < 4) {
        startPage = Math.max(1, endPage - 4);
    }
    
    for (var i = startPage; i <= endPage; i++) {
        if (i === currentPage) {
            html += '<li class="active"><span>' + i + '</span></li>';
        } else {
            html += '<li><a href="#" onclick="goToLogPage(' + i + '); return false;">' + i + '</a></li>';
        }
    }
    
    // Next button
    if (currentPage < totalPages) {
        html += '<li><a href="#" onclick="goToLogPage(' + (currentPage + 1) + '); return false;">Next &raquo;</a></li>';
    } else {
        html += '<li class="disabled"><span>Next &raquo;</span></li>';
    }
    
    html += '</ul>';
    $('#logsPagination').html(html);
}

function goToLogPage(page) {
    currentLogOffset = (page - 1) * currentLogLimit;
    loadSystemLogs();
}

function exportSystemLogs() {
    var url = docroot + '/admin_export_system_logs';
    var params = [];
    
    if (currentLogLevel) params.push('log_level=' + encodeURIComponent(currentLogLevel));
    if (currentLogCategory) params.push('log_category=' + encodeURIComponent(currentLogCategory));
    
    if (params.length > 0) {
        url += '?' + params.join('&');
    }
    
    window.open(url, '_blank');
}

function exportUserData() {
    window.open(docroot + '/admin_export_users', '_blank');
}

// Add CSS for activity items and modals
$('<style>')
    .prop('type', 'text/css')
    .html(`
        .stat-box {
            display: flex;
            align-items: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .stat-icon {
            font-size: 2.5em;
            margin-right: 20px;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        
        .activity-item {
            border-bottom: 1px solid #eee;
            padding: 10px 0;
        }
        
        .activity-item:last-child {
            border-bottom: none;
        }
        
        .activity-type {
            font-weight: bold;
            color: #333;
        }
        
        .activity-description {
            color: #666;
            font-size: 0.9em;
        }
        
        .activity-time {
            color: #999;
            font-size: 0.8em;
        }
        
        /* System Settings Modal Styles */
        #systemSettingsModal .list-group-item {
            transition: all 0.3s ease;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        
        #systemSettingsModal .list-group-item:hover {
            background-color: #f8f9fa;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        #systemSettingsModal .setting-input {
            border: 2px solid #e0e0e0;
            transition: border-color 0.3s ease;
        }
        
        #systemSettingsModal .setting-input:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        /* System Logs Modal Styles */
        #systemLogsTable thead th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            font-weight: 600;
        }
        
        #systemLogsTable tbody tr {
            transition: background-color 0.2s ease;
        }
        
        #systemLogsTable tbody tr:hover {
            background-color: #f8f9fa;
        }
        
        #systemLogsModal .label {
            font-size: 11px;
            padding: 4px 8px;
            font-weight: 600;
        }
        
        #systemLogsModal .pagination > li > a,
        #systemLogsModal .pagination > li > span {
            color: #667eea;
        }
        
        #systemLogsModal .pagination > .active > a,
        #systemLogsModal .pagination > .active > span {
            background-color: #667eea;
            border-color: #667eea;
        }
        
        /* Filter controls styling */
        #systemLogsModal .form-control {
            border: 2px solid #e0e0e0;
            transition: border-color 0.3s ease;
        }
        
        #systemLogsModal .form-control:focus {
            border-color: #f5576c;
            box-shadow: 0 0 0 0.2rem rgba(245, 87, 108, 0.25);
        }
        
        /* Scrollbar styling for logs table */
        #systemLogsModal .table-responsive::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        #systemLogsModal .table-responsive::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        #systemLogsModal .table-responsive::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 10px;
        }
        
        #systemLogsModal .table-responsive::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
    `)
    .appendTo('head');
