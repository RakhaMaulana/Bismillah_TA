/**
 * Enhanced Form Validation and UX
 * Provides real-time validation, better error messaging, and accessibility
 */

(function() {
    'use strict';

    // Form validation configuration
    const VALIDATION_CONFIG = {
        npm: {
            pattern: /^[0-9]{8,12}$/,
            minLength: 8,
            maxLength: 12,
            errorMessage: 'NPM must be 8-12 digits'
        },
        username: {
            pattern: /^[A-Za-z0-9_\-\.@]{3,50}$/,
            minLength: 3,
            maxLength: 50,
            errorMessage: 'Username must be 3-50 characters, alphanumeric with _-@. allowed'
        },
        password: {
            minLength: 8,
            maxLength: 128,
            errorMessage: 'Password must be at least 8 characters'
        },
        name: {
            pattern: /^[A-Za-z\s\-\']{2,50}$/,
            minLength: 2,
            maxLength: 50,
            errorMessage: 'Name must be 2-50 characters, letters only'
        }
    };

    // Initialize form validation when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        initializeFormValidation();
        setupErrorHandling();
        enhanceAccessibility();
    });

    function initializeFormValidation() {
        const forms = document.querySelectorAll('form[data-validation="true"], .needs-validation');

        forms.forEach(form => {
            setupFormValidation(form);
        });

        // Auto-detect forms that need validation
        const autoDetectForms = document.querySelectorAll('form:not([data-validation="false"])');
        autoDetectForms.forEach(form => {
            if (form.querySelectorAll('input[required], select[required], textarea[required]').length > 0) {
                setupFormValidation(form);
            }
        });
    }

    function setupFormValidation(form) {
        const inputs = form.querySelectorAll('input, select, textarea');

        inputs.forEach(input => {
            // Setup real-time validation
            setupInputValidation(input);

            // Enhance accessibility
            enhanceInputAccessibility(input);
        });

        // Setup form submission validation
        form.addEventListener('submit', function(e) {
            if (!validateForm(form)) {
                e.preventDefault();
                e.stopPropagation();

                // Focus on first invalid field
                const firstInvalid = form.querySelector('.is-invalid');
                if (firstInvalid) {
                    firstInvalid.focus();

                    // Scroll to field if needed
                    firstInvalid.scrollIntoView({
                        behavior: 'smooth',
                        block: 'center'
                    });
                }
            }
        });
    }

    function setupInputValidation(input) {
        // Real-time validation on input
        input.addEventListener('input', function() {
            validateInput(this);
        });

        // Validation on blur
        input.addEventListener('blur', function() {
            validateInput(this);
        });

        // Special handling for specific input types
        if (input.type === 'tel' || input.pattern === '^[0-9]{8,12}$') {
            // NPM/Phone number input
            input.addEventListener('keypress', function(e) {
                // Only allow numbers
                if (!/[0-9]/.test(e.key) && !['Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'Tab'].includes(e.key)) {
                    e.preventDefault();
                }
            });

            input.addEventListener('paste', function(e) {
                e.preventDefault();
                const paste = (e.clipboardData || window.clipboardData).getData('text');
                const sanitized = paste.replace(/[^0-9]/g, '').substring(0, this.maxLength || 12);
                this.value = sanitized;
                validateInput(this);
            });
        }
    }

    function validateInput(input) {
        const value = input.value.trim();
        const inputType = getInputType(input);

        // Clear previous validation state
        clearValidationState(input);

        // Skip validation if input is empty and not required
        if (!value && !input.required) {
            return true;
        }

        // Required field validation
        if (input.required && !value) {
            setValidationState(input, false, 'This field is required');
            return false;
        }

        // Type-specific validation
        let isValid = true;
        let errorMessage = '';

        switch (inputType) {
            case 'npm':
                isValid = validateNPM(value);
                errorMessage = VALIDATION_CONFIG.npm.errorMessage;
                break;
            case 'username':
                isValid = validateUsername(value);
                errorMessage = VALIDATION_CONFIG.username.errorMessage;
                break;
            case 'password':
                isValid = validatePassword(value);
                errorMessage = VALIDATION_CONFIG.password.errorMessage;
                break;
            case 'email':
                isValid = validateEmail(value);
                errorMessage = 'Please enter a valid email address';
                break;
            case 'name':
                isValid = validateName(value);
                errorMessage = VALIDATION_CONFIG.name.errorMessage;
                break;
            default:
                // Use HTML5 validation
                isValid = input.checkValidity();
                errorMessage = input.validationMessage;
        }

        setValidationState(input, isValid, errorMessage);
        return isValid;
    }

    function getInputType(input) {
        // Determine input type for validation
        if (input.name === 'id_number' || input.name === 'npm') return 'npm';
        if (input.name === 'username') return 'username';
        if (input.type === 'password') return 'password';
        if (input.type === 'email') return 'email';
        if (input.name === 'name' || input.name === 'full_name') return 'name';

        return 'default';
    }

    function validateNPM(value) {
        return VALIDATION_CONFIG.npm.pattern.test(value);
    }

    function validateUsername(value) {
        return VALIDATION_CONFIG.username.pattern.test(value);
    }

    function validatePassword(value) {
        return value.length >= VALIDATION_CONFIG.password.minLength;
    }

    function validateEmail(value) {
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailPattern.test(value);
    }

    function validateName(value) {
        return VALIDATION_CONFIG.name.pattern.test(value);
    }

    function setValidationState(input, isValid, errorMessage) {
        const formGroup = input.closest('.form-floating, .form-group, .mb-3, .mb-4');

        if (isValid) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            input.setAttribute('aria-invalid', 'false');

            // Hide error message
            hideErrorMessage(input);

            // Show success message if available
            showSuccessMessage(input);
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            input.setAttribute('aria-invalid', 'true');

            // Show error message
            showErrorMessage(input, errorMessage);

            // Hide success message
            hideSuccessMessage(input);
        }
    }

    function clearValidationState(input) {
        input.classList.remove('is-valid', 'is-invalid');
        input.removeAttribute('aria-invalid');
        hideErrorMessage(input);
        hideSuccessMessage(input);
    }

    function showErrorMessage(input, message) {
        let errorElement = input.parentNode.querySelector('.invalid-feedback');

        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'invalid-feedback';
            errorElement.setAttribute('role', 'alert');
            input.parentNode.appendChild(errorElement);
        }

        errorElement.innerHTML = `<i class="fas fa-exclamation-circle me-1" aria-hidden="true"></i>${message}`;
        errorElement.style.display = 'block';

        // Link error message to input for screen readers
        if (!input.getAttribute('aria-describedby')) {
            const errorId = 'error-' + Math.random().toString(36).substr(2, 9);
            errorElement.id = errorId;
            input.setAttribute('aria-describedby', errorId);
        }
    }

    function hideErrorMessage(input) {
        const errorElement = input.parentNode.querySelector('.invalid-feedback');
        if (errorElement) {
            errorElement.style.display = 'none';
        }
    }

    function showSuccessMessage(input) {
        let successElement = input.parentNode.querySelector('.valid-feedback');

        if (!successElement) {
            successElement = document.createElement('div');
            successElement.className = 'valid-feedback';
            input.parentNode.appendChild(successElement);
        }

        successElement.innerHTML = `<i class="fas fa-check-circle me-1" aria-hidden="true"></i>Looks good!`;
        successElement.style.display = 'block';
    }

    function hideSuccessMessage(input) {
        const successElement = input.parentNode.querySelector('.valid-feedback');
        if (successElement) {
            successElement.style.display = 'none';
        }
    }

    function validateForm(form) {
        const inputs = form.querySelectorAll('input, select, textarea');
        let isFormValid = true;

        inputs.forEach(input => {
            if (!validateInput(input)) {
                isFormValid = false;
            }
        });

        return isFormValid;
    }

    function setupErrorHandling() {
        // Handle form submission errors
        window.addEventListener('error', function(e) {
            console.error('Form error:', e.error);
        });

        // Handle fetch errors for AJAX forms
        document.addEventListener('submit', function(e) {
            const form = e.target;
            if (form.getAttribute('data-ajax') === 'true') {
                e.preventDefault();
                handleAjaxForm(form);
            }
        });
    }

    function enhanceAccessibility() {
        // Add ARIA labels and descriptions
        const inputs = document.querySelectorAll('input, select, textarea');

        inputs.forEach(input => {
            enhanceInputAccessibility(input);
        });

        // Enhance form labels
        const labels = document.querySelectorAll('label');
        labels.forEach(label => {
            if (!label.getAttribute('for') && label.querySelector('input, select, textarea')) {
                const input = label.querySelector('input, select, textarea');
                if (input && !input.id) {
                    const id = 'input-' + Math.random().toString(36).substr(2, 9);
                    input.id = id;
                    label.setAttribute('for', id);
                }
            }
        });
    }

    function enhanceInputAccessibility(input) {
        // Add ARIA attributes
        if (input.required && !input.getAttribute('aria-required')) {
            input.setAttribute('aria-required', 'true');
        }

        // Add input descriptions
        if (input.pattern && !input.getAttribute('aria-describedby')) {
            const description = getPatternDescription(input.pattern);
            if (description) {
                const descId = 'desc-' + Math.random().toString(36).substr(2, 9);
                const descElement = document.createElement('div');
                descElement.id = descId;
                descElement.className = 'form-text';
                descElement.textContent = description;
                input.parentNode.appendChild(descElement);
                input.setAttribute('aria-describedby', descId);
            }
        }

        // Enhance focus indicators
        input.addEventListener('focus', function() {
            this.parentNode.classList.add('focused');
        });

        input.addEventListener('blur', function() {
            this.parentNode.classList.remove('focused');
        });
    }

    function getPatternDescription(pattern) {
        // Return user-friendly descriptions for common patterns
        const patterns = {
            '^[0-9]{8,12}$': 'Enter 8-12 digits',
            '^[A-Za-z0-9_\\-\\.@]{3,50}$': 'Use 3-50 characters: letters, numbers, _, -, ., @',
            '^[A-Za-z\\s\\-\']{2,50}$': 'Use 2-50 characters: letters, spaces, hyphens, apostrophes'
        };

        return patterns[pattern] || null;
    }

    function handleAjaxForm(form) {
        const formData = new FormData(form);
        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');

        // Show loading state
        if (submitBtn) {
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';

            // Reset after timeout
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }, 5000);
        }

        fetch(form.action || window.location.href, {
            method: form.method || 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showFormMessage(form, 'success', data.message || 'Form submitted successfully!');
                form.reset();
            } else {
                showFormMessage(form, 'error', data.message || 'An error occurred. Please try again.');
            }
        })
        .catch(error => {
            console.error('Form submission error:', error);
            showFormMessage(form, 'error', 'Network error. Please check your connection and try again.');
        })
        .finally(() => {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }
        });
    }

    function showFormMessage(form, type, message) {
        let messageContainer = form.querySelector('.form-message');

        if (!messageContainer) {
            messageContainer = document.createElement('div');
            messageContainer.className = 'form-message';
            form.insertBefore(messageContainer, form.firstChild);
        }

        messageContainer.className = `form-message alert alert-${type === 'success' ? 'success' : 'danger'}`;
        messageContainer.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'} me-2"></i>
            ${message}
        `;

        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(() => {
                messageContainer.remove();
            }, 5000);
        }
    }

    // Export functions for use in other scripts
    window.FormValidator = {
        validateForm: validateForm,
        validateInput: validateInput,
        showFormMessage: showFormMessage
    };

})();
