/**
 * SOC Report Export Utility
 * Handles high-resolution PNG image captures and PDF report generation.
 * Uses dynamic CDN injection and native print fallbacks so Vite never fails to resolve bare modules.
 */

function loadExternalScript(src, globalVar) {
  return new Promise((resolve) => {
    if (typeof window !== 'undefined' && window[globalVar]) {
      return resolve(window[globalVar]);
    }
    if (typeof document === 'undefined') {
      return resolve(null);
    }
    const existingScript = document.querySelector(`script[src="${src}"]`);
    if (existingScript) {
      existingScript.addEventListener('load', () => resolve(window[globalVar]));
      existingScript.addEventListener('error', () => resolve(null));
      return;
    }
    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.onload = () => resolve(window[globalVar]);
    script.onerror = () => {
      console.warn(`Could not load external script: ${src}`);
      resolve(null);
    };
    document.head.appendChild(script);
  });
}

export async function exportElementAsImage(elementId, filename = 'SOC_Executive_Report') {
  const element = document.getElementById(elementId);
  if (!element) {
    console.error(`Export error: Element #${elementId} not found.`);
    window.print();
    return;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const fullFilename = `${filename}_${timestamp}.png`;

  try {
    const html2canvas = await loadExternalScript(
      'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js',
      'html2canvas'
    );

    if (!html2canvas) {
      console.info('html2canvas unavailable, launching native print / PDF export.');
      window.print();
      return;
    }

    const canvas = await html2canvas(element, {
      backgroundColor: '#070b14',
      scale: 2, // 2x scale for crisp, publication-ready resolution
      useCORS: true,
      logging: false,
      allowTaint: true,
      windowWidth: element.scrollWidth,
      windowHeight: element.scrollHeight,
    });

    const imageUri = canvas.toDataURL('image/png');
    const link = document.createElement('a');
    link.download = fullFilename;
    link.href = imageUri;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  } catch (err) {
    console.warn('Image capture failed, falling back to print dialog:', err);
    window.print();
  }
}

export async function exportElementAsPdf(elementId, filename = 'SOC_Incident_Report') {
  const element = document.getElementById(elementId);
  if (!element) {
    console.error(`Export error: Element #${elementId} not found.`);
    window.print();
    return;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const fullFilename = `${filename}_${timestamp}.pdf`;

  try {
    const html2canvas = await loadExternalScript(
      'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js',
      'html2canvas'
    );
    const jspdfObj = await loadExternalScript(
      'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
      'jspdf'
    );

    const jsPDF = jspdfObj?.jsPDF || (typeof window !== 'undefined' ? window.jsPDF : null);

    if (!html2canvas || !jsPDF) {
      console.info('PDF export library unavailable, launching native print / PDF export.');
      window.print();
      return;
    }

    const canvas = await html2canvas(element, {
      backgroundColor: '#070b14',
      scale: 2,
      useCORS: true,
      logging: false,
    });

    const imgData = canvas.toDataURL('image/png');
    const pdf = new jsPDF({
      orientation: canvas.width > canvas.height ? 'landscape' : 'portrait',
      unit: 'px',
      format: [canvas.width / 2, canvas.height / 2],
    });

    pdf.addImage(imgData, 'PNG', 0, 0, canvas.width / 2, canvas.height / 2);
    pdf.save(fullFilename);
  } catch (err) {
    console.warn('PDF export failed, falling back to print dialog:', err);
    window.print();
  }
}
