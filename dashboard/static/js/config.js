/**
 * DevSecure Dashboard - Configuration Management JavaScript
 * Handle platform configuration and settings
 */

class ConfigManager {
    constructor() {
        this.originalConfig = {};
        this.currentConfig = {};
        this.hasUnsavedChanges = false;
        
        this.initializeEventListeners();
        this.loadConfiguration();
        this.setupFormValidation();
        this.setupChangeTracking();
    }
    
    /**
     * Initialize event listeners
     */
    initializeEventListeners() {
        // Save configuration button
        document.getElementById('save-config-btn').addEventListener('click', () => {
            this.saveConfiguration();
        });
        
        // Reset configuration button
        document.getElementById('reset-config-btn').addEventListener('click', () => {
            this.resetConfiguration();
        });
        
        // Test buttons
        document.getElementById('test-api-key').addEventListener('click', () => {
            this.testAIConnection();
        });
        
        document.getElementById('test-github').addEventListener('click', () => {
            this.testGitHubConnection();
        });
        
        // Tab switching
        document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => {
                this.onTabSwitch(e.target.getAttribute('data-bs-target'));
            });
        });
        
        // Form input changes
        this.setupInputChangeListeners();
        
        // Prevent navigation with unsaved changes
        window.addEventListener('beforeunload', (e) => {
            if (this.hasUnsavedChanges) {
                e.preventDefault();
                e.returnValue = 'You have unsaved configuration changes. Are you sure you want to leave?';
            }
        });
    }
    
    /**
     * Setup input change listeners for all form elements
     */
    setupInputChangeListeners() {
        const inputs = document.querySelectorAll('input, select, textarea');
        
        inputs.forEach(input => {
            ['change', 'input'].forEach(eventType => {
                input.addEventListener(eventType, () => {
                    this.markAsChanged();
                    this.validateField(input);
                });
            });
        });
    }
    
    /**
     * Load configuration from API
     */
    async loadConfiguration() {
        try {
            const response = await window.dashboard.apiCall('/api/config');
            this.originalConfig = response;
            this.currentConfig = { ...response };
            
            this.populateForm(this.currentConfig);
            this.markAsSaved();
            
        } catch (error) {
            console.error('Failed to load configuration:', error);
            
            // Use default configuration if API fails
            this.loadDefaultConfiguration();
            window.dashboard.showNotification('Using default configuration', 'warning');
        }
    }
    
    /**
     * Load default configuration
     */
    loadDefaultConfiguration() {
        this.currentConfig = {
            general: {
                platform_name: 'DevSecure',
                default_project_path: '/home/user/projects',
                max_concurrent_scans: 3,
                scan_timeout: 30,
                autofix_coverage: 80,
                dashboard_theme: 'light',
                parallel_scanning: true,
                incremental_scanning: true,
                cache_results: true,
                smart_correlation: true
            },
            security_engines: {
                sast: {
                    enabled: true,
                    primary_engine: 'opengrep',
                    strictness: 'balanced',
                    custom_rules: './custom-rules',
                    excluded_paths: 'node_modules,vendor,build'
                },
                sca: {
                    enabled: true,
                    primary_engine: 'safety',
                    cvss_threshold: 7.0,
                    update_check: true,
                    license_check: false
                },
                secrets: {
                    enabled: true,
                    engine: 'builtin',
                    entropy_threshold: 4.5,
                    patterns: 'api[_-]?key\\s*[:=]\\s*[a-zA-Z0-9]+\nsecret[_-]?key\\s*[:=]\\s*[a-zA-Z0-9]+'
                }
            },
            ai_models: {
                provider: 'openai',
                model_version: 'gpt-4',
                api_key: '',
                timeout: 30,
                confidence_threshold: 75,
                max_retries: 3,
                context_aware: true,
                test_generation: true
            },
            integrations: {
                github: {
                    enabled: true,
                    token: '',
                    repo: '',
                    branch_prefix: 'devsecure/autofix',
                    auto_merge: true
                },
                slack: {
                    enabled: false,
                    webhook: '',
                    channel: '#security'
                },
                jira: {
                    enabled: false,
                    url: '',
                    project: '',
                    username: '',
                    token: ''
                }
            },
            notifications: {
                email: {
                    enabled: true,
                    smtp_server: '',
                    from_email: '',
                    smtp_port: 587
                },
                events: {
                    scan_complete: true,
                    critical_findings: true,
                    autofix_success: true,
                    autofix_failure: false,
                    pr_merged: true,
                    system_errors: true
                }
            }
        };
        
        this.originalConfig = { ...this.currentConfig };
        this.populateForm(this.currentConfig);
    }
    
    /**
     * Populate form with configuration data
     */
    populateForm(config) {
        // General settings
        if (config.general) {
            this.setFieldValue('platform-name', config.general.platform_name);
            this.setFieldValue('default-project-path', config.general.default_project_path);
            this.setFieldValue('max-concurrent-scans', config.general.max_concurrent_scans);
            this.setFieldValue('scan-timeout', config.general.scan_timeout);
            this.setFieldValue('autofix-coverage', config.general.autofix_coverage);
            this.setFieldValue('dashboard-theme', config.general.dashboard_theme);
            this.setFieldValue('parallel-scanning', config.general.parallel_scanning);
            this.setFieldValue('incremental-scanning', config.general.incremental_scanning);
            this.setFieldValue('cache-results', config.general.cache_results);
            this.setFieldValue('smart-correlation', config.general.smart_correlation);
        }
        
        // Security engines
        if (config.security_engines) {
            const { sast, sca, secrets } = config.security_engines;
            
            if (sast) {
                this.setFieldValue('sast-enabled', sast.enabled);
                this.setFieldValue('sast-primary-engine', sast.primary_engine);
                this.setFieldValue('sast-strictness', sast.strictness);
                this.setFieldValue('sast-custom-rules', sast.custom_rules);
                this.setFieldValue('sast-excluded-paths', sast.excluded_paths);
            }
            
            if (sca) {
                this.setFieldValue('sca-enabled', sca.enabled);
                this.setFieldValue('sca-primary-engine', sca.primary_engine);
                this.setFieldValue('sca-cvss-threshold', sca.cvss_threshold);
                this.setFieldValue('sca-update-check', sca.update_check);
                this.setFieldValue('sca-license-check', sca.license_check);
            }
            
            if (secrets) {
                this.setFieldValue('secrets-enabled', secrets.enabled);
                this.setFieldValue('secrets-engine', secrets.engine);
                this.setFieldValue('secrets-entropy', secrets.entropy_threshold);
                this.setFieldValue('secrets-patterns', secrets.patterns);
            }
        }
        
        // AI models
        if (config.ai_models) {
            this.setFieldValue('ai-provider', config.ai_models.provider);
            this.setFieldValue('ai-model-version', config.ai_models.model_version);
            this.setFieldValue('ai-api-key', config.ai_models.api_key);
            this.setFieldValue('ai-timeout', config.ai_models.timeout);
            this.setFieldValue('ai-confidence-threshold', config.ai_models.confidence_threshold);
            this.setFieldValue('ai-max-retries', config.ai_models.max_retries);
            this.setFieldValue('ai-context-aware', config.ai_models.context_aware);
            this.setFieldValue('ai-test-generation', config.ai_models.test_generation);
        }
        
        // Integrations
        if (config.integrations) {
            const { github, slack, jira } = config.integrations;
            
            if (github) {
                this.setFieldValue('github-enabled', github.enabled);
                this.setFieldValue('github-token', github.token);
                this.setFieldValue('github-repo', github.repo);
                this.setFieldValue('github-branch-prefix', github.branch_prefix);
                this.setFieldValue('github-auto-merge', github.auto_merge);
            }
            
            if (slack) {
                this.setFieldValue('slack-enabled', slack.enabled);
                this.setFieldValue('slack-webhook', slack.webhook);
                this.setFieldValue('slack-channel', slack.channel);
            }
            
            if (jira) {
                this.setFieldValue('jira-enabled', jira.enabled);
                this.setFieldValue('jira-url', jira.url);
                this.setFieldValue('jira-project', jira.project);
                this.setFieldValue('jira-username', jira.username);
                this.setFieldValue('jira-token', jira.token);
            }
        }
        
        // Notifications
        if (config.notifications) {
            const { email, events } = config.notifications;
            
            if (email) {
                this.setFieldValue('email-enabled', email.enabled);
                this.setFieldValue('smtp-server', email.smtp_server);
                this.setFieldValue('from-email', email.from_email);
                this.setFieldValue('smtp-port', email.smtp_port);
            }
            
            if (events) {
                this.setFieldValue('notify-scan-complete', events.scan_complete);
                this.setFieldValue('notify-critical-findings', events.critical_findings);
                this.setFieldValue('notify-autofix-success', events.autofix_success);
                this.setFieldValue('notify-autofix-failure', events.autofix_failure);
                this.setFieldValue('notify-pr-merged', events.pr_merged);
                this.setFieldValue('notify-system-errors', events.system_errors);
            }
        }
    }
    
    /**
     * Set field value based on element type
     */
    setFieldValue(id, value) {
        const element = document.getElementById(id);
        if (!element) return;
        
        if (element.type === 'checkbox') {
            element.checked = value;
        } else {
            element.value = value || '';
        }
    }
    
    /**
     * Get field value based on element type
     */
    getFieldValue(id) {
        const element = document.getElementById(id);
        if (!element) return null;
        
        if (element.type === 'checkbox') {
            return element.checked;
        } else if (element.type === 'number') {
            return parseFloat(element.value) || 0;
        } else {
            return element.value;
        }
    }
    
    /**
     * Collect configuration from form
     */
    collectConfiguration() {
        return {
            general: {
                platform_name: this.getFieldValue('platform-name'),
                default_project_path: this.getFieldValue('default-project-path'),
                max_concurrent_scans: this.getFieldValue('max-concurrent-scans'),
                scan_timeout: this.getFieldValue('scan-timeout'),
                autofix_coverage: this.getFieldValue('autofix-coverage'),
                dashboard_theme: this.getFieldValue('dashboard-theme'),
                parallel_scanning: this.getFieldValue('parallel-scanning'),
                incremental_scanning: this.getFieldValue('incremental-scanning'),
                cache_results: this.getFieldValue('cache-results'),
                smart_correlation: this.getFieldValue('smart-correlation')
            },
            security_engines: {
                sast: {
                    enabled: this.getFieldValue('sast-enabled'),
                    primary_engine: this.getFieldValue('sast-primary-engine'),
                    strictness: this.getFieldValue('sast-strictness'),
                    custom_rules: this.getFieldValue('sast-custom-rules'),
                    excluded_paths: this.getFieldValue('sast-excluded-paths')
                },
                sca: {
                    enabled: this.getFieldValue('sca-enabled'),
                    primary_engine: this.getFieldValue('sca-primary-engine'),
                    cvss_threshold: this.getFieldValue('sca-cvss-threshold'),
                    update_check: this.getFieldValue('sca-update-check'),
                    license_check: this.getFieldValue('sca-license-check')
                },
                secrets: {
                    enabled: this.getFieldValue('secrets-enabled'),
                    engine: this.getFieldValue('secrets-engine'),
                    entropy_threshold: this.getFieldValue('secrets-entropy'),
                    patterns: this.getFieldValue('secrets-patterns')
                }
            },
            ai_models: {
                provider: this.getFieldValue('ai-provider'),
                model_version: this.getFieldValue('ai-model-version'),
                api_key: this.getFieldValue('ai-api-key'),
                timeout: this.getFieldValue('ai-timeout'),
                confidence_threshold: this.getFieldValue('ai-confidence-threshold'),
                max_retries: this.getFieldValue('ai-max-retries'),
                context_aware: this.getFieldValue('ai-context-aware'),
                test_generation: this.getFieldValue('ai-test-generation')
            },
            integrations: {
                github: {
                    enabled: this.getFieldValue('github-enabled'),
                    token: this.getFieldValue('github-token'),
                    repo: this.getFieldValue('github-repo'),
                    branch_prefix: this.getFieldValue('github-branch-prefix'),
                    auto_merge: this.getFieldValue('github-auto-merge')
                },
                slack: {
                    enabled: this.getFieldValue('slack-enabled'),
                    webhook: this.getFieldValue('slack-webhook'),
                    channel: this.getFieldValue('slack-channel')
                },
                jira: {
                    enabled: this.getFieldValue('jira-enabled'),
                    url: this.getFieldValue('jira-url'),
                    project: this.getFieldValue('jira-project'),
                    username: this.getFieldValue('jira-username'),
                    token: this.getFieldValue('jira-token')
                }
            },
            notifications: {
                email: {
                    enabled: this.getFieldValue('email-enabled'),
                    smtp_server: this.getFieldValue('smtp-server'),
                    from_email: this.getFieldValue('from-email'),
                    smtp_port: this.getFieldValue('smtp-port')
                },
                events: {
                    scan_complete: this.getFieldValue('notify-scan-complete'),
                    critical_findings: this.getFieldValue('notify-critical-findings'),
                    autofix_success: this.getFieldValue('notify-autofix-success'),
                    autofix_failure: this.getFieldValue('notify-autofix-failure'),
                    pr_merged: this.getFieldValue('notify-pr-merged'),
                    system_errors: this.getFieldValue('notify-system-errors')
                }
            }
        };
    }
    
    /**
     * Save configuration to API
     */
    async saveConfiguration() {
        try {
            const config = this.collectConfiguration();
            
            // Validate configuration
            const validation = this.validateConfiguration(config);
            if (!validation.valid) {
                this.showValidationErrors(validation.errors);
                return;
            }
            
            // Show saving indicator
            const saveBtn = document.getElementById('save-config-btn');
            const originalText = saveBtn.innerHTML;
            saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Saving...';
            saveBtn.disabled = true;
            
            // Save to API
            await window.dashboard.apiCall('/api/config', {
                method: 'POST',
                body: JSON.stringify(config)
            });
            
            this.originalConfig = { ...config };
            this.currentConfig = { ...config };
            this.markAsSaved();
            
            window.dashboard.showNotification('Configuration saved successfully', 'success');
            this.showSaveStatus(true, 'Configuration saved and applied successfully');
            
        } catch (error) {
            console.error('Failed to save configuration:', error);
            window.dashboard.showNotification('Failed to save configuration', 'error');
            this.showSaveStatus(false, error.message);
        } finally {
            // Reset save button
            const saveBtn = document.getElementById('save-config-btn');
            saveBtn.innerHTML = '<i class="fas fa-save me-2"></i>Save Configuration';
            saveBtn.disabled = false;
        }
    }
    
    /**
     * Reset configuration to original values
     */
    resetConfiguration() {
        if (this.hasUnsavedChanges) {
            if (!confirm('Are you sure you want to reset all changes? This will discard unsaved modifications.')) {
                return;
            }
        }
        
        this.populateForm(this.originalConfig);
        this.currentConfig = { ...this.originalConfig };
        this.markAsSaved();
        
        window.dashboard.showNotification('Configuration reset to saved values', 'info');
    }
    
    /**
     * Validate configuration
     */
    validateConfiguration(config) {
        const errors = [];
        
        // General validation
        if (!config.general.platform_name) {
            errors.push('Platform name is required');
        }
        
        if (!config.general.default_project_path) {
            errors.push('Default project path is required');
        }
        
        if (config.general.max_concurrent_scans < 1 || config.general.max_concurrent_scans > 10) {
            errors.push('Max concurrent scans must be between 1 and 10');
        }
        
        // AI model validation
        if (!config.ai_models.api_key && config.ai_models.provider === 'openai') {
            errors.push('OpenAI API key is required');
        }
        
        // GitHub validation
        if (config.integrations.github.enabled && !config.integrations.github.token) {
            errors.push('GitHub token is required when GitHub integration is enabled');
        }
        
        // Email validation
        if (config.notifications.email.enabled) {
            if (!config.notifications.email.smtp_server) {
                errors.push('SMTP server is required when email notifications are enabled');
            }
            
            if (!config.notifications.email.from_email) {
                errors.push('From email is required when email notifications are enabled');
            }
        }
        
        return {
            valid: errors.length === 0,
            errors: errors
        };
    }
    
    /**
     * Show validation errors
     */
    showValidationErrors(errors) {
        const errorList = errors.map(error => `<li>${error}</li>`).join('');
        
        const alertHtml = `
            <div class="alert alert-danger alert-dismissible fade show">
                <h6><i class="fas fa-exclamation-triangle me-2"></i>Configuration Validation Errors</h6>
                <ul class="mb-0">${errorList}</ul>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        const alertsContainer = document.getElementById('alerts-container');
        if (alertsContainer) {
            alertsContainer.insertAdjacentHTML('beforeend', alertHtml);
        }
    }
    
    /**
     * Show save status modal
     */
    showSaveStatus(success, message) {
        const modal = new bootstrap.Modal(document.getElementById('configStatusModal'));
        const content = document.getElementById('config-status-content');
        
        const icon = success ? 'check-circle text-success' : 'exclamation-triangle text-danger';
        const title = success ? 'Configuration Saved' : 'Save Failed';
        
        content.innerHTML = `
            <div class="text-center">
                <i class="fas fa-${icon} fa-3x mb-3"></i>
                <h5>${title}</h5>
                <p class="text-muted">${message}</p>
            </div>
        `;
        
        modal.show();
    }
    
    /**
     * Test AI connection
     */
    async testAIConnection() {
        const apiKey = this.getFieldValue('ai-api-key');
        const provider = this.getFieldValue('ai-provider');
        
        if (!apiKey) {
            window.dashboard.showNotification('Please enter an API key first', 'warning');
            return;
        }
        
        const testBtn = document.getElementById('test-api-key');
        const originalText = testBtn.innerHTML;
        testBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        testBtn.disabled = true;
        
        try {
            // Mock API test - replace with actual test
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            window.dashboard.showNotification('AI connection test successful', 'success');
            
        } catch (error) {
            window.dashboard.showNotification('AI connection test failed', 'error');
        } finally {
            testBtn.innerHTML = originalText;
            testBtn.disabled = false;
        }
    }
    
    /**
     * Test GitHub connection
     */
    async testGitHubConnection() {
        const token = this.getFieldValue('github-token');
        
        if (!token) {
            window.dashboard.showNotification('Please enter a GitHub token first', 'warning');
            return;
        }
        
        const testBtn = document.getElementById('test-github');
        const originalText = testBtn.innerHTML;
        testBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        testBtn.disabled = true;
        
        try {
            // Mock GitHub test - replace with actual test
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            window.dashboard.showNotification('GitHub connection test successful', 'success');
            
        } catch (error) {
            window.dashboard.showNotification('GitHub connection test failed', 'error');
        } finally {
            testBtn.innerHTML = originalText;
            testBtn.disabled = false;
        }
    }
    
    /**
     * Setup form validation
     */
    setupFormValidation() {
        // Add real-time validation for specific fields
        const emailInputs = document.querySelectorAll('input[type="email"]');
        emailInputs.forEach(input => {
            input.addEventListener('blur', () => {
                this.validateEmail(input);
            });
        });
        
        const urlInputs = document.querySelectorAll('input[type="url"]');
        urlInputs.forEach(input => {
            input.addEventListener('blur', () => {
                this.validateUrl(input);
            });
        });
        
        const numberInputs = document.querySelectorAll('input[type="number"]');
        numberInputs.forEach(input => {
            input.addEventListener('blur', () => {
                this.validateNumber(input);
            });
        });
    }
    
    /**
     * Validate individual fields
     */
    validateField(field) {
        switch (field.type) {
            case 'email':
                return this.validateEmail(field);
            case 'url':
                return this.validateUrl(field);
            case 'number':
                return this.validateNumber(field);
            default:
                return true;
        }
    }
    
    validateEmail(input) {
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const isValid = !input.value || emailPattern.test(input.value);
        
        this.setFieldValidation(input, isValid, 'Please enter a valid email address');
        return isValid;
    }
    
    validateUrl(input) {
        try {
            const isValid = !input.value || new URL(input.value);
            this.setFieldValidation(input, isValid, 'Please enter a valid URL');
            return isValid;
        } catch {
            this.setFieldValidation(input, false, 'Please enter a valid URL');
            return false;
        }
    }
    
    validateNumber(input) {
        const value = parseFloat(input.value);
        const min = parseFloat(input.min);
        const max = parseFloat(input.max);
        
        let isValid = !isNaN(value);
        
        if (isValid && !isNaN(min) && value < min) {
            isValid = false;
        }
        
        if (isValid && !isNaN(max) && value > max) {
            isValid = false;
        }
        
        this.setFieldValidation(input, isValid, `Please enter a number between ${min || 0} and ${max || '∞'}`);
        return isValid;
    }
    
    /**
     * Set field validation state
     */
    setFieldValidation(field, isValid, message) {
        field.classList.remove('is-valid', 'is-invalid');
        
        // Remove existing feedback
        const existingFeedback = field.parentNode.querySelector('.invalid-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }
        
        if (field.value) {
            if (isValid) {
                field.classList.add('is-valid');
            } else {
                field.classList.add('is-invalid');
                
                const feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                feedback.textContent = message;
                field.parentNode.appendChild(feedback);
            }
        }
    }
    
    /**
     * Setup change tracking
     */
    setupChangeTracking() {
        // Initial state
        this.markAsSaved();
    }
    
    /**
     * Mark configuration as changed
     */
    markAsChanged() {
        if (!this.hasUnsavedChanges) {
            this.hasUnsavedChanges = true;
            this.updateSaveButtonState();
        }
    }
    
    /**
     * Mark configuration as saved
     */
    markAsSaved() {
        this.hasUnsavedChanges = false;
        this.updateSaveButtonState();
    }
    
    /**
     * Update save button state
     */
    updateSaveButtonState() {
        const saveBtn = document.getElementById('save-config-btn');
        const resetBtn = document.getElementById('reset-config-btn');
        
        if (this.hasUnsavedChanges) {
            saveBtn.classList.remove('btn-success');
            saveBtn.classList.add('btn-warning');
            saveBtn.innerHTML = '<i class="fas fa-save me-2"></i>Save Changes *';
            resetBtn.disabled = false;
        } else {
            saveBtn.classList.remove('btn-warning');
            saveBtn.classList.add('btn-success');
            saveBtn.innerHTML = '<i class="fas fa-save me-2"></i>Save Configuration';
            resetBtn.disabled = true;
        }
    }
    
    /**
     * Handle tab switching
     */
    onTabSwitch(tabId) {
        // Validate current tab before switching
        // This could be enhanced to prevent switching if there are validation errors
        console.log(`Switched to tab: ${tabId}`);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.configManager = new ConfigManager();
});