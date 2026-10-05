/* =============================================================
   SOC Dashboard — Global JavaScript
   =============================================================
   Loaded on every page via base.html. Handles UI behaviours that
   apply across the whole application. Page-specific JavaScript
   (charts, quizzes, audio, confetti) lives in the individual
   templates.
   ============================================================= */

console.log('SOC Dashboard loaded');

// Auto-dismiss flash messages (success, warning, danger banners)
// after 5 seconds so they don't clutter the page.
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 5000);
    });
});
