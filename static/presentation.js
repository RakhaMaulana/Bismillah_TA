// Enhanced JavaScript for E-Voting Presentation
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all animations and interactions
    initScrollAnimations();
    initSecurityScoreCounter();
    initFlowStepAnimations();
    initParallaxEffect();
    initTooltips();
    initProgressBars();

    // Add interactive elements
    addClickableElements();
    addKeyboardNavigation();
});

// Smooth scroll animations with intersection observer
function initScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                const element = entry.target;
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';

                // Add specific animations based on element class
                if (element.classList.contains('feature-card')) {
                    animateFeatureCard(element);
                } else if (element.classList.contains('stat-card')) {
                    animateStatCard(element);
                }

                observer.unobserve(element);
            }
        });
    }, observerOptions);

    // Observe all cards and animated elements
    document.querySelectorAll('.card, .feature-card, .stat-card').forEach((element) => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(50px)';
        element.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
        observer.observe(element);
    });
}

// Animate security score counter
function initSecurityScoreCounter() {
    const scoreElements = document.querySelectorAll('.stat-number');

    scoreElements.forEach(element => {
        const target = element.textContent;
        if (target === '100%' || target === '100') {
            animateCounter(element, 0, 100, 2000, '%');
        } else if (target.includes('s')) {
            // Handle time values like "<1s"
            element.innerHTML = '<span class="highlight">&lt;1</span>s';
        }
    });
}

function animateCounter(element, start, end, duration, suffix = '') {
    let startTime = null;
    element.textContent = start + suffix;

    function updateCounter(timestamp) {
        if (!startTime) startTime = timestamp;
        const progress = Math.min((timestamp - startTime) / duration, 1);

        const current = Math.floor(progress * (end - start) + start);
        element.textContent = current + suffix;

        if (progress < 1) {
            requestAnimationFrame(updateCounter);
        } else {
            // Add pulse effect when complete
            element.style.animation = 'pulse 0.5s ease';
            setTimeout(() => {
                element.style.animation = '';
            }, 500);
        }
    }

    requestAnimationFrame(updateCounter);
}

// Animate flow steps sequentially
function initFlowStepAnimations() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                const flowSteps = entry.target.querySelectorAll('.flow-step');
                flowSteps.forEach((step, index) => {
                    setTimeout(() => {
                        step.style.opacity = '1';
                        step.style.transform = 'translateX(0)';
                        step.style.animation = 'slideInLeft 0.6s ease forwards';
                    }, index * 300);
                });
                observer.unobserve(entry.target);
            }
        });
    });

    const flowcharts = document.querySelectorAll('.flowchart');
    flowcharts.forEach(flowchart => {
        const steps = flowchart.querySelectorAll('.flow-step');
        steps.forEach(step => {
            step.style.opacity = '0';
            step.style.transform = 'translateX(-50px)';
        });
        observer.observe(flowchart);
    });
}

// Add parallax effect to hero section
function initParallaxEffect() {
    const hero = document.querySelector('.hero');
    if (!hero) return;

    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        const rate = scrolled * -0.5;
        hero.style.transform = `translateY(${rate}px)`;
    });
}

// Add tooltips to technical terms
function initTooltips() {
    const technicalTerms = {
        'Blind Signature': 'Teknik kriptografi yang memungkinkan penandatanganan dokumen tanpa mengetahui isinya',
        'RSA': 'Algoritma enkripsi asimetris yang sangat aman menggunakan pasangan kunci publik-privat',
        'STRIDE': 'Model ancaman keamanan: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege',
        'Flask': 'Framework web Python yang ringan dan fleksibel untuk pengembangan aplikasi web',
        'SQLite': 'Database SQL yang embedded, tidak memerlukan server terpisah',
        'SSL/TLS': 'Protokol keamanan untuk enkripsi komunikasi web'
    };

    Object.keys(technicalTerms).forEach(term => {
        const elements = document.querySelectorAll(`*:not(script):not(style)`);
        elements.forEach(element => {
            if (element.childNodes.length === 1 && element.childNodes[0].nodeType === 3) {
                const text = element.textContent;
                if (text.includes(term)) {
                    element.innerHTML = text.replace(
                        new RegExp(term, 'g'),
                        `<span class="tooltip" title="${technicalTerms[term]}">${term}</span>`
                    );
                }
            }
        });
    });

    // Add tooltip styles
    const style = document.createElement('style');
    style.textContent = `
        .tooltip {
            position: relative;
            cursor: help;
            border-bottom: 1px dotted #667eea;
        }

        .tooltip::after {
            content: attr(title);
            position: absolute;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 0.8rem;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s;
            z-index: 1000;
        }

        .tooltip:hover::after {
            opacity: 1;
        }
    `;
    document.head.appendChild(style);
}

// Add progress bars for security features
function initProgressBars() {
    const securityFeatures = [
        { name: 'Encryption', score: 100 },
        { name: 'Authentication', score: 95 },
        { name: 'Privacy', score: 100 },
        { name: 'Integrity', score: 98 },
        { name: 'Availability', score: 96 }
    ];

    const progressContainer = document.createElement('div');
    progressContainer.className = 'security-progress-container';
    progressContainer.innerHTML = `
        <h3>📊 Security Metrics</h3>
        ${securityFeatures.map(feature => `
            <div class="progress-item">
                <div class="progress-label">${feature.name}</div>
                <div class="progress-bar">
                    <div class="progress-fill" data-score="${feature.score}"></div>
                </div>
                <div class="progress-score">${feature.score}%</div>
            </div>
        `).join('')}
    `;

    // Add to security section
    const securityCard = document.querySelector('.card');
    if (securityCard) {
        securityCard.appendChild(progressContainer);
    }

    // Animate progress bars
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                const progressFills = entry.target.querySelectorAll('.progress-fill');
                progressFills.forEach((fill, index) => {
                    setTimeout(() => {
                        const score = fill.getAttribute('data-score');
                        fill.style.width = score + '%';
                    }, index * 200);
                });
                observer.unobserve(entry.target);
            }
        });
    });

    observer.observe(progressContainer);

    // Add progress bar styles
    const style = document.createElement('style');
    style.textContent = `
        .security-progress-container {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            margin: 30px 0;
        }

        .progress-item {
            display: flex;
            align-items: center;
            margin: 15px 0;
            gap: 15px;
        }

        .progress-label {
            min-width: 120px;
            font-weight: bold;
            color: #495057;
        }

        .progress-bar {
            flex: 1;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(45deg, #28a745, #20c997);
            width: 0%;
            transition: width 1s ease;
            border-radius: 10px;
        }

        .progress-score {
            min-width: 50px;
            font-weight: bold;
            color: #28a745;
        }
    `;
    document.head.appendChild(style);
}

// Add clickable interactions
function addClickableElements() {
    // Add click effects to cards
    document.querySelectorAll('.card').forEach(card => {
        card.addEventListener('click', function(e) {
            // Add ripple effect
            const ripple = document.createElement('div');
            ripple.className = 'ripple-effect';

            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;

            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';

            this.appendChild(ripple);

            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });

    // Add ripple effect styles
    const style = document.createElement('style');
    style.textContent = `
        .card {
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }

        .ripple-effect {
            position: absolute;
            border-radius: 50%;
            background: rgba(102, 126, 234, 0.3);
            transform: scale(0);
            animation: ripple 0.6s linear;
        }

        @keyframes ripple {
            to {
                transform: scale(4);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
}

// Add keyboard navigation
function addKeyboardNavigation() {
    let currentFocus = 0;
    const focusableElements = document.querySelectorAll('.card, .demo-button, .tech-item');

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Tab') {
            e.preventDefault();

            if (e.shiftKey) {
                currentFocus = currentFocus > 0 ? currentFocus - 1 : focusableElements.length - 1;
            } else {
                currentFocus = currentFocus < focusableElements.length - 1 ? currentFocus + 1 : 0;
            }

            focusableElements[currentFocus].focus();
            focusableElements[currentFocus].scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    });
}

// Animate feature cards individually
function animateFeatureCard(card) {
    const icon = card.querySelector('.feature-icon');
    if (icon) {
        icon.style.transform = 'scale(1.2)';
        setTimeout(() => {
            icon.style.transform = 'scale(1)';
        }, 300);
    }
}

// Animate stat cards with counter effect
function animateStatCard(card) {
    const statNumber = card.querySelector('.stat-number');
    if (statNumber) {
        const text = statNumber.textContent;
        const number = parseInt(text);

        if (!isNaN(number) && number > 0) {
            animateCounter(statNumber, 0, number, 1500);
        }
    }
}

// Add download functionality for reports
function addDownloadButtons() {
    const buttons = document.querySelectorAll('.demo-button[href$=".json"], .demo-button[href$=".pdf"]');
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            // Add download animation
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = 'scale(1)';
            }, 150);
        });
    });
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addDownloadButtons);
} else {
    addDownloadButtons();
}
