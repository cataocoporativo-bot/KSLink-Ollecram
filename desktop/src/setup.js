'use strict';
const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);

if (params.get('erro')) {
  $('erro').textContent = params.get('erro');
  $('erro').hidden = false;
}

(async () => {
  try {
    $('srv').value = (await window.kslink.getServer()) || params.get('saved') || '';
  } catch {
    /* campo vazio */
  }
  $('srv').focus();
})();

async function salvar() {
  const btn = $('salvar');
  btn.disabled = true;
  $('msg').hidden = true;
  try {
    const r = await window.kslink.saveServer($('srv').value);
    if (!r.ok) {
      $('msg').textContent = r.error;
      $('msg').hidden = false;
      btn.disabled = false;
    }
  } catch {
    $('msg').textContent = 'Falha ao salvar.';
    $('msg').hidden = false;
    btn.disabled = false;
  }
}

$('salvar').addEventListener('click', salvar);
$('srv').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') salvar();
});
