(function () {
  function qs(sel) { return document.querySelector(sel); }
  function show(id, on) {
    var row = qs('#' + id) || qs('[id="id_' + id + '"]');
    if (!row) return;
    // in the admin, each field is wrapped in a .form-row or .field-xxx
    var wrapper = row.closest('.form-row, .field-' + id) || row.closest('div');
    if (wrapper) wrapper.style.display = on ? '' : 'none';
  }

  function toggle() {
    var method = qs('#id_method') ? qs('#id_method').value : 'import';
    var internal = (method === 'internal');

    // Internal-only fields
    [
      'id_issuer_mode','id_issuer_parent','id_key_type','id_digest_algo','id_lifetime_days',
      'id_common_name','id_country_code','id_state','id_city',
      'id_organization','id_organizational_unit','id_email','id_ocsp_uri'
    ].forEach(function(id){ show(id, internal); });

    // Import-only helpers (file uploads)
    ['id_cert_file','id_key_file', 'id_cert_pem', 'id_key_pem'].forEach(function(id){
      show(id, !internal);
    });

    // Issuer parent visibility
    var mode = qs('#id_issuer_mode') ? qs('#id_issuer_mode').value : 'self';
    show('id_issuer_parent', internal && mode === 'parent');
  }

  document.addEventListener('change', function (e) {
    if (e.target && (e.target.id === 'id_method' || e.target.id === 'id_issuer_mode')) {
      toggle();
    }
  });

  document.addEventListener('DOMContentLoaded', toggle);
})();
