// Lucide Icons Render Init
document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initNavigation();
  initFileUpload();
});

// Single Page View Navigation Manager
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-item');
  
  navButtons.forEach(button => {
    button.addEventListener('click', () => {
      const targetViewId = button.getAttribute('data-target');
      navigateTo(targetViewId);
    });
  });
}

function navigateTo(viewId) {
  // Hide all active views
  document.querySelectorAll('.page-view').forEach(view => {
    view.classList.remove('active');
  });

  // Deactivate all sidebar nav buttons
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.remove('active');
    
    // Remove Aurora edge indicator
    const edge = btn.querySelector('.aurora-edge');
    if (edge) edge.remove();
  });

  // Activate target view
  const targetView = document.getElementById(viewId);
  if (targetView) {
    targetView.classList.add('active');
  }

  // Highlight corresponding sidebar button
  const activeBtn = document.querySelector(`.nav-item[data-target="${viewId}"]`);
  if (activeBtn) {
    activeBtn.classList.add('active');
    
    // Inject Aurora Edge
    const auroraEdge = document.createElement('span');
    auroraEdge.className = 'aurora-edge';
    activeBtn.prepend(auroraEdge);
  }
}

// Drag & Drop File Upload Handler
function initFileUpload() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');

  if (!dropzone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--ice)';
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--border-color)';
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleUploadedFile(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleUploadedFile(e.target.files[0]);
    }
  });
}

function handleUploadedFile(file) {
  const specSummary = document.getElementById('specSummary');
  const fileName = document.getElementById('fileName');
  const fileMeta = document.getElementById('fileMeta');

  fileName.textContent = file.name;
  fileMeta.textContent = `OpenAPI Parsed • ${(file.size / 1024).toFixed(1)} KB`;
  specSummary.style.display = 'flex';
}

function startScanProcess() {
  alert('Initiating automated security scan sequence against uploaded spec...');
  navigateTo('dashboard');
}