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

function showSystemSettings() {
    alertify.alert('System Settings', 'System settings functionality will be implemented in future updates.');
}

function exportUserData() {
    window.open(docroot + '/admin_export_users', '_blank');
}

function viewSystemLogs() {
    alertify.alert('System Logs', 'System logs functionality will be implemented in future updates.');
}

// Add CSS for activity items
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
    `)
    .appendTo('head');
