/**
 * Server-rendered, script-free viewer for shared BambooKit sessions. All content is escaped;
 * the route sets a CSP that forbids scripts entirely.
 */
const esc = (v: unknown) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** Minimal, safe markdown: fenced code blocks, inline code, bold, paragraphs. Input is escaped first. */
function md(text: string): string {
  const parts = String(text ?? '').split(/```/);
  return parts
    .map((chunk, i) => {
      if (i % 2 === 1) {
        const nl = chunk.indexOf('\n');
        const code = nl >= 0 ? chunk.slice(nl + 1) : chunk;
        return `<pre><code>${esc(code.replace(/\n$/, ''))}</code></pre>`;
      }
      return esc(chunk)
        .replace(/`([^`\n]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
        .split(/\n{2,}/)
        .map((p) => (p.trim() ? `<p>${p.replace(/\n/g, '<br>')}</p>` : ''))
        .join('');
    })
    .join('');
}

const STYLE = `
:root{--bg:#121212;--fg:#e5edd5;--muted:#9aa394;--line:#262a24;--panel:#181a17;--user:#1f241c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:10px}
header b{letter-spacing:.02em}header span{color:var(--muted);font-size:13px}
main{max-width:860px;margin:0 auto;padding:24px 20px 80px}
h1{font-size:22px;margin:0 0 4px}.meta{color:var(--muted);font-size:13px;margin-bottom:24px}
.msg{margin:14px 0}.user{background:var(--user);border:1px solid var(--line);border-radius:8px;padding:10px 14px}
.role{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:4px}
.tool{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);padding:2px 0}
.tool .s-completed{color:#9fd39a}.tool .s-error{color:#ef8a80}
pre{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px;overflow:auto;font:13px/1.5 ui-monospace,Consolas,monospace}
code{font-family:ui-monospace,Consolas,monospace;background:var(--panel);padding:1px 4px;border-radius:4px}pre code{background:none;padding:0}
.files{border:1px solid var(--line);border-radius:8px;margin-top:28px}.files div{display:flex;justify-content:space-between;padding:6px 12px;border-top:1px solid var(--line);font:13px ui-monospace,Consolas,monospace}
.files div:first-child{border-top:0;color:var(--muted);font-family:inherit}.add{color:#9fd39a}.del{color:#ef8a80}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px}
`;

const LOGO = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M13 2.5l1.6.3-2.9 19.2-1.6-.3z" fill="#e5edd5"/><path d="M11.4 9.2C9 7.6 6.8 7.3 4.5 8c2.3 1.3 4.3 1.9 6.7 1.6zM12.6 14.6c2.6-1.1 4.8-1 7 .1-2.4.9-4.5 1.1-7 .3zM12 7.8c-.6-2.4.1-4.3 1.6-5.8.3 2.2-.1 4-1.6 5.8z" fill="#e5edd5"/></svg>`;

export function renderSharePage(share: { opencode_session_id: string; updated_at: string } | null, items: Array<{ type: string; data: any }>): string {
  const head = (title: string) =>
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} · BambooKit</title><style>${STYLE}</style></head><body><header>${LOGO}<b>BambooKit</b><span>Shared session</span></header>`;
  if (!share) return `${head('Not found')}<main><h1>This shared session does not exist</h1><p class="meta">It may have been unpublished.</p></main></body></html>`;

  const session = items.find((i) => i.type === 'session')?.data ?? {};
  const messages = items.filter((i) => i.type === 'message').map((i) => i.data).sort((a, b) => (a?.time?.created ?? 0) - (b?.time?.created ?? 0));
  const parts = items.filter((i) => i.type === 'part').map((i) => i.data);
  const diff: any[] = items.find((i) => i.type === 'session_diff')?.data ?? [];
  const byMessage = new Map<string, any[]>();
  for (const p of parts) byMessage.set(p.messageID, [...(byMessage.get(p.messageID) ?? []), p]);

  const body = messages
    .map((m) => {
      const ps = (byMessage.get(m.id) ?? []).sort((a, b) => String(a.id).localeCompare(String(b.id)));
      const content = ps
        .map((p) => {
          if (p.type === 'text' && !p.synthetic && !p.ignored) return md(p.text);
          if (p.type === 'tool') {
            const status = p.state?.status ?? '';
            const title = p.state?.title || p.state?.input?.command || p.state?.input?.filePath || '';
            return `<div class="tool">▸ ${esc(p.tool)} ${esc(title)} <span class="s-${esc(status)}">${esc(status)}</span></div>`;
          }
          return '';
        })
        .join('');
      if (!content) return '';
      if (m.role === 'user') return `<div class="msg user"><div class="role">You</div>${content}</div>`;
      const model = m.modelID ? ` · ${esc(m.modelID)}` : '';
      return `<div class="msg"><div class="role">Agent${model}</div>${content}</div>`;
    })
    .join('');

  const files = diff.length
    ? `<div class="files"><div><span>${diff.length} file${diff.length === 1 ? '' : 's'} changed</span><span></span></div>${diff
        .map((f) => `<div><span>${esc(f.file)}</span><span><span class="add">+${esc(f.additions)}</span> <span class="del">−${esc(f.deletions)}</span></span></div>`)
        .join('')}</div>`
    : '';

  const updated = new Date(share.updated_at).toUTCString();
  return `${head(session.title || 'Session')}<main><h1>${esc(session.title || 'Session')}</h1><div class="meta">Updated ${esc(updated)}</div>${body || '<p class="meta">This session has no messages yet.</p>'}${files}</main><footer>Shared from BambooKit Desktop</footer></body></html>`;
}
