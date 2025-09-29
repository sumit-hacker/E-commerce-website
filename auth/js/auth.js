/**
 * Authentication System JavaScript
 * 
 * Client-side validation, UX enhancements, and interactive features
 * for the authentication system with modern ES6+ features.
 * 
 * @author Sumit
 * @version 1.0
 */

'use strict';

// ========== AUTHENTICATION CLASS ==========
class AuthSystem {
    constructor() {
        this.initializeEventListeners();
        this.initializeValidation();
        this.initializeFormEnhancements();
        this.initializePasswordStrength();
        this.initializeCSRFProtection();
    }

    // ========== EVENT LISTENERS ==========
    initializeEventListeners() {
        // Form submissions
        document.addEventListener('submit', this.handleFormSubmit.bind(this));
        
        // Input validations
        document.addEventListener('input', this.handleInputValidation.bind(this));
        document.addEventListener('blur', this.handleInputBlur.bind(this), true);
        
        // Password visibility toggles
        document.addEventListener('click', this.handlePasswordToggle.bind(this));
        
        // Alert dismissals
        document.addEventListener('click', this.handleAlertDismiss.bind(this));
        
        // Window events
        window.addEventListener('load', this.handlePageLoad.bind(this));
        window.addEventListener('beforeunload', this.handlePageUnload.bind(this));
    }

    // ========== FORM HANDLING ==========
    handleFormSubmit(event) {
        const form = event.target;
        if (!form.classList.contains('auth-form')) return;

        event.preventDefault();
        
        // Show loading state
        this.setFormLoading(form, true);
        
        // Validate form
        const validation = this.validateForm(form);
        if (!validation.isValid) {
            this.setFormLoading(form, false);
            this.showValidationErrors(form, validation.errors);
            return;
        }

        // Submit form via AJAX
        this.submitForm(form);
    }

    async submitForm(form) {
        try {
            const formData = new FormData(form);
            const response = await fetch(form.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            const result = await response.json();
            
            this.setFormLoading(form, false);
            
            if (result.success) {
                this.handleSuccessResponse(result);
            } else {
                this.handleErrorResponse(result);
            }
            
        } catch (error) {
            this.setFormLoading(form, false);
            this.showAlert('An error occurred. Please try again.', 'error');
            console.error('Form submission error:', error);
        }
    }

    handleSuccessResponse(result) {
        this.showAlert(result.message || 'Operation completed successfully!', 'success');
        
        // Handle redirects
        if (result.redirect) {
            setTimeout(() => {
                window.location.href = result.redirect;
            }, 1500);
        }
        
        // Handle specific success actions
        if (result.action) {
            this.handleSpecialActions(result.action, result);
        }
    }

    handleErrorResponse(result) {
        if (result.errors) {
            if (Array.isArray(result.errors)) {
                result.errors.forEach(error => {
                    this.showAlert(error, 'error');
                });
            } else if (typeof result.errors === 'object') {
                this.showFieldErrors(result.errors);
            }
        } else {
            this.showAlert(result.message || 'An error occurred.', 'error');
        }
    }

    handleSpecialActions(action, result) {
        switch (action) {
            case 'verification_needed':
                this.showVerificationPrompt(result);
                break;
            case 'two_factor_required':
                this.showTwoFactorForm(result);
                break;
            case 'password_expired':
                this.showPasswordChangeForm(result);
                break;
        }
    }

    // ========== FORM VALIDATION ==========
    initializeValidation() {
        this.validationRules = {
            email: {
                pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                message: 'Please enter a valid email address'
            },
            username: {
                pattern: /^[a-zA-Z0-9_.-]{3,30}$/,
                message: 'Username must be 3-30 characters (letters, numbers, dots, hyphens, underscores only)'
            },
            password: {
                minLength: 8,
                pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
                message: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character'
            },
            name: {
                pattern: /^[a-zA-Z\s'-]{1,100}$/,
                message: 'Name can only contain letters, spaces, hyphens, and apostrophes'
            },
            phone: {
                pattern: /^[\d\s\-\+\(\)]{10,20}$/,
                message: 'Please enter a valid phone number'
            }
        };
    }

    validateForm(form) {
        const errors = [];
        const formData = new FormData(form);
        
        // Validate required fields
        form.querySelectorAll('input[required], select[required], textarea[required]').forEach(field => {
            if (!field.value.trim()) {
                errors.push({
                    field: field.name,
                    message: `${this.getFieldLabel(field)} is required`
                });
            }
        });

        // Validate field formats
        form.querySelectorAll('input[data-validate]').forEach(field => {
            const validationType = field.dataset.validate;
            const validation = this.validateField(field.value, validationType);
            
            if (!validation.isValid) {
                errors.push({
                    field: field.name,
                    message: validation.message
                });
            }
        });

        // Custom validations
        this.performCustomValidations(form, errors);

        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }

    validateField(value, type) {
        if (!value) return { isValid: true }; // Skip empty values (handled by required check)
        
        const rule = this.validationRules[type];
        if (!rule) return { isValid: true };

        let isValid = true;
        let message = rule.message;

        // Check pattern
        if (rule.pattern && !rule.pattern.test(value)) {
            isValid = false;
        }

        // Check length
        if (rule.minLength && value.length < rule.minLength) {
            isValid = false;
            message = `Must be at least ${rule.minLength} characters long`;
        }

        if (rule.maxLength && value.length > rule.maxLength) {
            isValid = false;
            message = `Must not exceed ${rule.maxLength} characters`;
        }

        return { isValid, message };
    }

    performCustomValidations(form, errors) {
        // Password confirmation
        const password = form.querySelector('input[name="password"]');
        const confirmPassword = form.querySelector('input[name="confirm_password"]');
        
        if (password && confirmPassword && password.value !== confirmPassword.value) {
            errors.push({
                field: 'confirm_password',
                message: 'Passwords do not match'
            });
        }

        // Terms acceptance
        const termsCheckbox = form.querySelector('input[name="accept_terms"]');
        if (termsCheckbox && !termsCheckbox.checked) {
            errors.push({
                field: 'accept_terms',
                message: 'You must accept the terms and conditions'
            });
        }
    }

    handleInputValidation(event) {
        const input = event.target;
        if (!input.dataset.validate) return;

        // Debounce validation
        clearTimeout(input.validationTimeout);
        input.validationTimeout = setTimeout(() => {
            this.validateSingleField(input);
        }, 300);
    }

    handleInputBlur(event) {
        const input = event.target;
        if (input.tagName === 'INPUT' || input.tagName === 'SELECT' || input.tagName === 'TEXTAREA') {
            this.validateSingleField(input);
        }
    }

    validateSingleField(field) {
        const validationType = field.dataset.validate;
        if (!validationType) return;

        const validation = this.validateField(field.value, validationType);
        const formGroup = field.closest('.form-group');
        
        this.clearFieldValidation(formGroup);
        
        if (field.value && !validation.isValid) {
            this.showFieldError(formGroup, validation.message);
        } else if (field.value && validation.isValid) {
            this.showFieldSuccess(formGroup);
        }
    }

    // ========== PASSWORD STRENGTH ==========
    initializePasswordStrength() {
        document.querySelectorAll('input[type="password"][data-validate="password"]').forEach(input => {
            this.setupPasswordStrength(input);
        });
    }

    setupPasswordStrength(passwordInput) {
        const formGroup = passwordInput.closest('.form-group');
        
        // Create strength indicator
        const strengthIndicator = document.createElement('div');
        strengthIndicator.className = 'password-strength';
        strengthIndicator.innerHTML = '<div class="password-strength-bar"></div>';
        
        // Create requirements list
        const requirements = document.createElement('div');
        requirements.className = 'password-requirements';
        requirements.innerHTML = `
            <ul>
                <li data-requirement="length">At least 8 characters</li>
                <li data-requirement="lowercase">One lowercase letter</li>
                <li data-requirement="uppercase">One uppercase letter</li>
                <li data-requirement="number">One number</li>
                <li data-requirement="special">One special character</li>
            </ul>
        `;
        
        formGroup.appendChild(strengthIndicator);
        formGroup.appendChild(requirements);
        
        // Add event listener
        passwordInput.addEventListener('input', (e) => {
            this.updatePasswordStrength(e.target, strengthIndicator, requirements);
        });
    }

    updatePasswordStrength(input, strengthIndicator, requirements) {
        const password = input.value;
        const strengthBar = strengthIndicator.querySelector('.password-strength-bar');
        const requirementItems = requirements.querySelectorAll('li');
        
        if (password.length === 0) {
            strengthIndicator.classList.remove('show');
            return;
        }
        
        strengthIndicator.classList.add('show');
        
        // Check requirements
        const checks = {
            length: password.length >= 8,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            number: /\d/.test(password),
            special: /[@$!%*?&]/.test(password)
        };
        
        // Update requirement indicators
        requirementItems.forEach(item => {
            const requirement = item.dataset.requirement;
            if (checks[requirement]) {
                item.classList.add('valid');
            } else {
                item.classList.remove('valid');
            }
        });
        
        // Calculate strength
        const score = Object.values(checks).filter(Boolean).length;
        let strengthClass = 'weak';
        
        if (score >= 5) strengthClass = 'strong';
        else if (score >= 4) strengthClass = 'good';
        else if (score >= 3) strengthClass = 'fair';
        
        // Update strength bar
        strengthBar.className = `password-strength-bar ${strengthClass}`;
    }

    // ========== FORM ENHANCEMENTS ==========
    initializeFormEnhancements() {
        this.setupPasswordToggles();
        this.setupInputAnimations();
        this.setupFormProgress();
    }

    setupPasswordToggles() {
        document.querySelectorAll('input[type="password"]').forEach(input => {
            const toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'password-toggle';
            toggle.innerHTML = '👁️';
            toggle.setAttribute('aria-label', 'Show password');
            
            const wrapper = document.createElement('div');
            wrapper.className = 'password-wrapper';
            
            input.parentNode.insertBefore(wrapper, input);
            wrapper.appendChild(input);
            wrapper.appendChild(toggle);
        });
    }

    handlePasswordToggle(event) {
        if (!event.target.classList.contains('password-toggle')) return;
        
        const passwordInput = event.target.previousElementSibling;
        const isPassword = passwordInput.type === 'password';
        
        passwordInput.type = isPassword ? 'text' : 'password';
        event.target.innerHTML = isPassword ? '🙈' : '👁️';
        event.target.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    }

    setupInputAnimations() {
        document.querySelectorAll('input, select, textarea').forEach(input => {
            input.addEventListener('focus', () => {
                input.closest('.form-group').classList.add('focused');
            });
            
            input.addEventListener('blur', () => {
                input.closest('.form-group').classList.remove('focused');
            });
        });
    }

    setupFormProgress() {
        const forms = document.querySelectorAll('.multi-step-form');
        forms.forEach(form => {
            this.initializeMultiStepForm(form);
        });
    }

    // ========== CSRF PROTECTION ==========
    initializeCSRFProtection() {
        // Add CSRF token to all forms
        document.querySelectorAll('form').forEach(form => {
            if (!form.querySelector('input[name="csrf_token"]')) {
                this.addCSRFToken(form);
            }
        });
    }

    async addCSRFToken(form) {
        try {
            const response = await fetch('/auth/get-csrf-token.php');
            const data = await response.json();
            
            if (data.token) {
                const tokenInput = document.createElement('input');
                tokenInput.type = 'hidden';
                tokenInput.name = 'csrf_token';
                tokenInput.value = data.token;
                form.appendChild(tokenInput);
            }
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
        }
    }

    // ========== UI HELPERS ==========
    setFormLoading(form, loading) {
        const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
        
        if (loading) {
            submitButton.classList.add('btn-loading');
            submitButton.disabled = true;
            form.style.pointerEvents = 'none';
        } else {
            submitButton.classList.remove('btn-loading');
            submitButton.disabled = false;
            form.style.pointerEvents = 'auto';
        }
    }

    showAlert(message, type = 'info', duration = 5000) {
        const alertContainer = this.getOrCreateAlertContainer();
        
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} slide-up`;
        alert.innerHTML = `
            ${message}
            <button class="close" data-dismiss="alert">&times;</button>
        `;
        
        alertContainer.appendChild(alert);
        
        // Auto-dismiss
        if (duration > 0) {
            setTimeout(() => {
                this.dismissAlert(alert);
            }, duration);
        }
    }

    getOrCreateAlertContainer() {
        let container = document.querySelector('.alert-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'alert-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 400px;
            `;
            document.body.appendChild(container);
        }
        return container;
    }

    handleAlertDismiss(event) {
        if (event.target.dataset.dismiss === 'alert') {
            this.dismissAlert(event.target.closest('.alert'));
        }
    }

    dismissAlert(alert) {
        alert.style.animation = 'slideUp 0.3s ease reverse';
        setTimeout(() => {
            if (alert.parentNode) {
                alert.parentNode.removeChild(alert);
            }
        }, 300);
    }

    showValidationErrors(form, errors) {
        // Clear previous errors
        form.querySelectorAll('.error-message').forEach(error => error.remove());
        form.querySelectorAll('.form-group').forEach(group => {
            group.classList.remove('has-error');
        });

        // Show new errors
        errors.forEach(error => {
            if (error.field) {
                const field = form.querySelector(`[name="${error.field}"]`);
                if (field) {
                    this.showFieldError(field.closest('.form-group'), error.message);
                }
            } else {
                this.showAlert(error.message, 'error');
            }
        });
    }

    showFieldErrors(errors) {
        Object.keys(errors).forEach(fieldName => {
            const field = document.querySelector(`[name="${fieldName}"]`);
            if (field) {
                const messages = Array.isArray(errors[fieldName]) ? errors[fieldName] : [errors[fieldName]];
                messages.forEach(message => {
                    this.showFieldError(field.closest('.form-group'), message);
                });
            }
        });
    }

    showFieldError(formGroup, message) {
        formGroup.classList.add('has-error');
        formGroup.classList.remove('has-success');
        
        const errorElement = document.createElement('span');
        errorElement.className = 'error-message';
        errorElement.textContent = message;
        
        formGroup.appendChild(errorElement);
    }

    showFieldSuccess(formGroup) {
        formGroup.classList.add('has-success');
        formGroup.classList.remove('has-error');
        
        // Remove any existing error messages
        const errorMessages = formGroup.querySelectorAll('.error-message');
        errorMessages.forEach(error => error.remove());
    }

    clearFieldValidation(formGroup) {
        formGroup.classList.remove('has-error', 'has-success');
        formGroup.querySelectorAll('.error-message, .success-message').forEach(msg => msg.remove());
    }

    getFieldLabel(field) {
        const label = field.closest('.form-group').querySelector('label');
        return label ? label.textContent.replace('*', '').trim() : field.name;
    }

    // ========== PAGE LIFECYCLE ==========
    handlePageLoad() {
        // Add fade-in animation to containers
        document.querySelectorAll('.auth-container, .dashboard-container').forEach(container => {
            container.classList.add('fade-in');
        });

        // Initialize tooltips and other UI enhancements
        this.initializeTooltips();
    }

    handlePageUnload() {
        // Clean up any pending timeouts or intervals
        document.querySelectorAll('input').forEach(input => {
            if (input.validationTimeout) {
                clearTimeout(input.validationTimeout);
            }
        });
    }

    initializeTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.addEventListener('mouseenter', this.showTooltip.bind(this));
            element.addEventListener('mouseleave', this.hideTooltip.bind(this));
        });
    }

    showTooltip(event) {
        const element = event.target;
        const tooltipText = element.dataset.tooltip;
        
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = tooltipText;
        tooltip.style.cssText = `
            position: absolute;
            background: #333;
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 14px;
            z-index: 10000;
            white-space: nowrap;
            pointer-events: none;
        `;
        
        document.body.appendChild(tooltip);
        
        const rect = element.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
        
        element._tooltip = tooltip;
    }

    hideTooltip(event) {
        const element = event.target;
        if (element._tooltip) {
            element._tooltip.remove();
            delete element._tooltip;
        }
    }

    // ========== UTILITY FUNCTIONS ==========
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    formatDate(date) {
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        }).format(new Date(date));
    }
}

// ========== INITIALIZATION ==========
document.addEventListener('DOMContentLoaded', () => {
    window.authSystem = new AuthSystem();
});

// ========== GLOBAL UTILITIES ==========
window.AuthUtils = {
    showAlert: (message, type, duration) => {
        if (window.authSystem) {
            window.authSystem.showAlert(message, type, duration);
        }
    },
    
    validateEmail: (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },
    
    generatePassword: (length = 12) => {
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@$!%*?&';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    },
    
    copyToClipboard: async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            window.AuthUtils.showAlert('Copied to clipboard!', 'success', 2000);
        } catch (err) {
            console.error('Failed to copy text: ', err);
            window.AuthUtils.showAlert('Failed to copy to clipboard', 'error');
        }
    },
    
    formatFileSize: (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

// ========== EXPORT FOR MODULE SYSTEMS ==========
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthSystem;
}