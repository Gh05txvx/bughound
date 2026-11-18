// app.js: small UI helpers (no dependencies). Loaded once through base.html;
// the global functions are called from onclick attributes, including on content
// inserted by HTMX (inline handlers still run after a swap).

// bhCopy copies the text of the <pre> block right after the button toolbar
// (.ev-head) to the clipboard, to paste into Burp Repeater during manual
// verification. It uses the Clipboard API (available on localhost/HTTPS) with an
// execCommand fallback when accessed over a non-secure IP. It gives brief
// feedback on the button label.
function bhCopy(btn) {
  var head = btn.closest('.ev-head');
  var pre = head ? head.nextElementSibling : null;
  if (!pre) return;
  var text = pre.innerText;
  var done = function () {
    var old = btn.textContent;
    btn.textContent = 'Copied ✓';
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
    // Stay silent: copying is a convenience, not a critical path.
  }
}

// bhLoadFile loads a file into a textarea on the browser side: the server only
// needs to accept an ordinary form, and the file content can still be seen and
// edited before it is sent.
function bhLoadFile(input, targetId) {
  var file = input.files && input.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function () { document.getElementById(targetId).value = reader.result; };
  reader.readAsText(file);
}
