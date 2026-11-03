// app.js — helper UI kecil (tanpa dependency). Dimuat sekali lewat base.html;
// fungsi global dipanggil dari atribut onclick, termasuk pada konten yang
// disisipkan HTMX (handler inline tetap berjalan setelah swap).

// bhCopy menyalin teks blok <pre> tepat setelah toolbar tombol (.ev-head) ke
// clipboard, untuk ditempel ke Burp Repeater saat verifikasi manual. Memakai
// Clipboard API (tersedia di localhost/HTTPS) dengan fallback execCommand bila
// diakses lewat IP non-secure. Memberi umpan balik singkat di label tombol.
function bhCopy(btn) {
  var head = btn.closest('.ev-head');
  var pre = head ? head.nextElementSibling : null;
  if (!pre) return;
  var text = pre.innerText;
  var done = function () {
    var old = btn.textContent;
    btn.textContent = 'Tersalin ✓';
    btn.disabled = true;
    setTimeout(function () { btn.textContent = old; btn.disabled = false; }, 1400);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () { bhCopyFallback(text, done); });
  } else {
    bhCopyFallback(text, done);
  }
}

function bhCopyFallback(text, done) {
  try {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    done();
  } catch (e) {
    // Diam saja: menyalin adalah kemudahan, bukan jalur kritis.
  }
}
