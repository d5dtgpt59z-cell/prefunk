(() => {
  const form = document.querySelector('#scan-form[data-api]');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button');
    const token = form.querySelector('[name="_csrf"]').value;
    const url = form.querySelector('[name="url"]').value;
    button.disabled = true;
    button.textContent = 'Checking…';
    try {
      const response = await fetch(form.dataset.api, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
        body: JSON.stringify({url})
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'The scan could not start.');
      window.location.assign(result.report_url);
    } catch (error) {
      button.disabled = false;
      button.textContent = 'Run free scan';
      window.alert(error.message);
    }
  });
})();
