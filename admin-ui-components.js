function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

const STAT_CARD_COLORS = new Set([
  'blue',
  'green',
  'purple',
  'orange',
  'slate',
  'pink',
  'cyan',
  'amber'
]);

/**
 * Shared Sponsor.krd-style statistic card.
 * The icon markup is trusted server-owned SVG; all visible data is escaped.
 */
export function renderStatCard({ icon, label, value, color = 'blue', subtitle = '' }) {
  const variant = STAT_CARD_COLORS.has(color) ? color : 'blue';
  return `<article class="shared-stat-card shared-stat-${variant}">
    <span class="shared-stat-icon">${icon}</span>
    <span class="shared-stat-copy">
      <strong>${escapeHtml(value)}</strong>
      <span>${escapeHtml(label)}</span>
      ${subtitle ? `<small>${escapeHtml(subtitle)}</small>` : ''}
    </span>
  </article>`;
}

/** Shared responsive grid used by every dashboard statistic group. */
export function renderStatCardGrid(cards, { columns = 4, className = '' } = {}) {
  const safeColumns = [2, 3, 4, 5, 6].includes(columns) ? columns : 4;
  return `<section class="shared-stat-grid shared-stat-grid-${safeColumns} ${escapeHtml(className)}" aria-label="پوختەی دەستگەیشتن">
    ${cards.join('')}
  </section>`;
}
