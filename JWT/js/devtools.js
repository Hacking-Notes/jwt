// Create a panel in Chrome DevTools
chrome.devtools.panels.create(
  "JWT", // Panel title
  null, // Icon path (optional)
  "panel.html", // Panel HTML page
  (panel) => {
    // Panel created callback
    console.log("JWT panel created");
  }
); 