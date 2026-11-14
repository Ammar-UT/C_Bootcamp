/**
 * ============================================================================
 * Cyber Bootcamp - Assignment 14: DOM Interaction & DOM-Based XSS Prevention
 * File: app.js
 * Description: Client-side JavaScript tool demonstrating the difference between
 *              unsafe execution sinks (innerHTML) and secure sinks (textContent).
 * ============================================================================
 */

// Wait for the DOM to finish loading before binding event listeners
document.addEventListener("DOMContentLoaded", () => {
    // ------------------------------------------------------------------------
    // 1. Element References (DOM Selectors)
    // ------------------------------------------------------------------------
    const inputField = document.getElementById("userInput");
    const btnRenderUnsafe = document.getElementById("btnRenderUnsafe");
    const btnRenderSafe = document.getElementById("btnRenderSafe");
    const btnClear = document.getElementById("btnClear");
    
    const outputUnsafe = document.getElementById("outputUnsafe");
    const outputSafe = document.getElementById("outputSafe");

    // ------------------------------------------------------------------------
    // 2. Unsafe Render Function (Demonstrating DOM-Based XSS Vulnerability)
    // ------------------------------------------------------------------------
    /**
     * Renders user input unsafely using `innerHTML`.
     * 
     * Security Risk Explanation:
     * When data is written directly to `innerHTML`, the browser's HTML parser
     * interprets the string as markup and executable code. If the input contains
     * elements with inline event handlers (e.g. <img src=x onerror=alert(1)>),
     * an attacker can execute arbitrary JavaScript in the context of the user's
     * session. This constitutes a classic DOM-based Cross-Site Scripting (DOM XSS) flaw.
     */
    function renderUnsafe() {
        // Step 1: Capture user input value
        const rawInput = inputField.value;

        if (!rawInput.trim()) {
            outputUnsafe.innerHTML = '<span class="placeholder-text">Please enter some text or select a payload above.</span>';
            return;
        }

        // Step 2: Directly assign input to innerHTML (Vulnerable Sink)
        // Notice: The browser parses HTML tags and triggers any associated scripts or handlers.
        outputUnsafe.innerHTML = rawInput;

        console.warn("[SECURITY AUDIT] Rendered via innerHTML (Vulnerable sink). Any embedded tags or handlers will execute.");
    }

    // ------------------------------------------------------------------------
    // 3. Safe Render Function (Remediating DOM-Based XSS)
    // ------------------------------------------------------------------------
    /**
     * Renders user input safely using `textContent` and programmatic DOM creation.
     * 
     * Defense-in-Depth Explanation:
     * The `textContent` property treats all passed data strictly as literal text.
     * Characters like '<', '>', '&', and '"' are never parsed as HTML elements,
     * tags, or event attributes. Even if an attacker supplies an XSS payload,
     * it will be rendered harmlessly on screen as plain text characters.
     */
    function renderSafe() {
        // Step 1: Capture user input value
        const rawInput = inputField.value;

        if (!rawInput.trim()) {
            outputSafe.textContent = "Please enter some text or select a payload above.";
            outputSafe.className = "output-area placeholder-text";
            return;
        }

        outputSafe.className = "output-area";

        // Step 2: Use safe DOM manipulation (document.createElement and textContent)
        // Clear previous content safely
        outputSafe.textContent = "";

        // Create a structured container element
        const safeWrapper = document.createElement("div");
        safeWrapper.className = "safe-rendered-content";

        // Assign input strictly as plain text (Secure Sink)
        safeWrapper.textContent = rawInput;

        // Append to DOM tree
        outputSafe.appendChild(safeWrapper);

        console.info("[SECURITY AUDIT] Rendered safely via textContent / appendChild. All inputs neutralized as literal strings.");
    }

    // ------------------------------------------------------------------------
    // 4. Helper Function: Reset / Clear Outputs
    // ------------------------------------------------------------------------
    function clearAll() {
        inputField.value = "";
        outputUnsafe.innerHTML = '<span class="placeholder-text">Unsafe output will appear here...</span>';
        outputSafe.textContent = "Safe output will appear here...";
        outputSafe.className = "output-area placeholder-text";
        inputField.focus();
    }

    // ------------------------------------------------------------------------
    // 5. Helper Function: Quick Payload Insertion
    // ------------------------------------------------------------------------
    window.setPayload = function(payload) {
        inputField.value = payload;
        inputField.focus();
    };

    // ------------------------------------------------------------------------
    // 6. Event Listeners
    // ------------------------------------------------------------------------
    btnRenderUnsafe.addEventListener("click", renderUnsafe);
    btnRenderSafe.addEventListener("click", renderSafe);
    btnClear.addEventListener("click", clearAll);

    // Optional convenience: Allow testing with Enter key (defaults to Safe Render)
    inputField.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && event.ctrlKey) {
            renderUnsafe();
        }
    });
});

