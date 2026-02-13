document.addEventListener('DOMContentLoaded', () => {
    window.app = new AgberoApp();
    window.app.init();
});

// Make UI functions available globally for inline event handlers
window.UI = UI;
window.Modal = Modal;
window.Drawer = Drawer;