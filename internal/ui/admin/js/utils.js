const Utils = {
    fmtNum(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
        if (n >= 1000) return (n / 1000).toFixed(1) + "k";
        return n || 0;
    },

    formatBytes(b) {
        if (!b || b === 0) return "0";
        const k = 1024, s = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(b) / Math.log(k));
        return parseFloat((b / Math.pow(k, i)).toFixed(1)) + s[i];
    },

    timeAgo(timestamp) {
        const seconds = Math.floor((Date.now() - timestamp) / 1000);
        if (seconds < 10) return 'just now';
        if (seconds < 60) return `${seconds}s ago`;
        return `${Math.floor(seconds / 60)}m ago`;
    },

    getBackendHealth(b, hasStats) {
        if (!hasStats) return { status: 'unknown', dotColor: 'warn' };
        if (b.healthy !== undefined) {
            return {
                status: b.healthy ? 'ok' : 'down',
                dotColor: b.healthy ? 'ok' : 'down'
            };
        }
        if (b.alive !== undefined) {
            const isTCP = b.url && !b.url.startsWith('http');
            return {
                status: isTCP ? (b.alive ? 'ok' : 'warn') : (b.alive ? 'ok' : 'down'),
                dotColor: isTCP ? (b.alive ? 'ok' : 'warn') : (b.alive ? 'ok' : 'down')
            };
        }
        return { status: 'unknown', dotColor: 'warn' };
    },

    getProtocolBadge(protocol) {
        const proto = (protocol || 'http').toUpperCase();
        const cls = proto === 'HTTP' ? 'success' : 'info';
        return `<span class="badge ${cls}">${proto}</span>`;
    }
};
