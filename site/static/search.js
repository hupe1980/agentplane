// Local documentation search, loaded lazily.
//
// The form works without any of this: it submits to GitHub's repository search,
// which is a real answer rather than a dead input. This upgrades it to instant
// local results — and deliberately fetches nothing until the box is focused,
// because the index is larger than every page on the site put together.
(() => {
  const form = document.getElementById('search-form');
  if (!form) return;
  const input = document.getElementById('search-input');
  const panel = document.getElementById('search-results');
  const base = form.dataset.base || '';

  let index = null;      // elasticlunr index, once loaded
  let loading = null;    // in-flight load, so focus+type does not fetch twice

  const script = (src) => new Promise((ok, fail) => {
    const el = document.createElement('script');
    el.src = src; el.onload = ok; el.onerror = fail;
    document.head.appendChild(el);
  });

  async function load() {
    if (index) return index;
    if (loading) return loading;
    loading = (async () => {
      await script(`${base}/elasticlunr.min.js`);
      await script(`${base}/search_index.en.js`);
      // eslint-disable-next-line no-undef
      index = elasticlunr.Index.load(window.searchIndex);
      return index;
    })();
    return loading;
  }

  const escape = (s) => s.replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  // A snippet centred on the first hit reads far better than the opening words
  // of a page, which are the same for every result on a docs site.
  function snippet(body, term) {
    const at = body.toLowerCase().indexOf(term.toLowerCase());
    if (at < 0) return escape(body.slice(0, 140)) + '…';
    const from = Math.max(0, at - 60);
    const text = (from ? '…' : '') + body.slice(from, at + 100) + '…';
    return escape(text).replace(new RegExp(`(${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'ig'), '<mark>$1</mark>');
  }

  function render(results, term) {
    if (!results.length) {
      panel.innerHTML = `<p class="empty">Nothing for “${escape(term)}”. <button type="submit" form="search-form">Search the repository instead</button></p>`;
    } else {
      panel.innerHTML = '<ul>' + results.slice(0, 8).map((r) => {
        const d = r.doc;
        return `<li><a href="${d.id}"><strong>${escape(d.title)}</strong>
          <span>${snippet(d.body || d.description || '', term)}</span></a></li>`;
      }).join('') + '</ul>';
    }
    panel.hidden = false;
    input.setAttribute('aria-expanded', 'true');
  }

  function close() {
    panel.hidden = true;
    input.setAttribute('aria-expanded', 'false');
  }

  input.addEventListener('focus', load, { once: true });

  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    const term = input.value.trim();
    if (term.length < 2) return close();
    timer = setTimeout(async () => {
      const idx = await load();
      render(idx.search(term, { bool: 'AND', expand: true }), term);
    }, 120);
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { close(); input.blur(); }
    if (e.key === 'ArrowDown' && !panel.hidden) {
      e.preventDefault();
      panel.querySelector('a')?.focus();
    }
  });

  document.addEventListener('click', (e) => {
    if (!form.contains(e.target) && !panel.contains(e.target)) close();
  });

  // `/` focuses search, the convention every docs site now shares.
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== input &&
        !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) {
      e.preventDefault(); input.focus();
    }
  });
})();
