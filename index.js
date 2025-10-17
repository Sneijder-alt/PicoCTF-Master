// Sample walkthrough data
const walkthroughs = [
    {
        id: 1,
        title: "Obedient Cat",
        platform: "picoCTF",
        category: "misc",
        difficulty: "beginner",
        points: 5,
        views: 15234,
        description: "Simple file examination challenge to understand basic CTF mechanics.",
        solution: "This challenge provides you with a file. Simply open the file using cat command or any text editor to find the flag directly inside.",
        steps: [
            "Download the provided file",
            "Open terminal and navigate to the file location",
            "Run: cat flag.txt",
            "The flag will be displayed directly"
        ],
        tools: ["cat", "text editor"],
        learningPoints: "Understanding basic file operations and flag formats"
    },
    {
        id: 2,
        title: "Web Gauntlet",
        platform: "picoCTF",
        category: "web",
        difficulty: "intermediate",
        points: 200,
        views: 8756,
        description: "SQL injection challenge with multiple filters to bypass.",
        solution: "This challenge requires bypassing SQL injection filters through various techniques including comment injection and alternative syntax.",
        steps: [
            "Identify the login form vulnerable to SQL injection",
            "Try basic payloads: admin' OR 1=1--",
            "If blocked, use alternative syntax: admin'||'1'='1",
            "Use comments to bypass filters: admin'/**/OR/**/1=1#",
            "Chain techniques for each filter level"
        ],
        tools: ["Burp Suite", "Browser DevTools"],
        learningPoints: "SQL injection techniques, filter bypass methods, understanding web security"
    },
    {
        id: 3,
        title: "Caesar Cipher",
        platform: "picoCTF",
        category: "crypto",
        difficulty: "beginner",
        points: 100,
        views: 12543,
        description: "Classic Caesar cipher decryption challenge.",
        solution: "Decrypt the message by trying all possible rotation values (ROT1-ROT25) until you find readable text.",
        steps: [
            "Understand Caesar cipher shifts each letter by n positions",
            "Use online tools or write a script to try all 25 rotations",
            "Look for the rotation that produces readable English text",
            "Extract the flag from the decrypted message"
        ],
        tools: ["CyberChef", "Python script"],
        learningPoints: "Basic cryptography, brute force approach, pattern recognition"
    },
    {
        id: 4,
        title: "Glory of the Garden",
        platform: "picoCTF",
        category: "forensics",
        difficulty: "beginner",
        points: 50,
        views: 11234,
        description: "Image forensics challenge hiding data in plain sight.",
        solution: "The flag is hidden in the image file but not visible. Use strings command to extract ASCII text from the binary.",
        steps: [
            "Download the image file",
            "Run: strings garden.jpg | grep pico",
            "The flag will appear in the output",
            "Alternative: open in hex editor and scroll to the end"
        ],
        tools: ["strings", "hexeditor", "exiftool"],
        learningPoints: "File metadata analysis, hidden data in images, using strings command"
    },
    {
        id: 5,
        title: "Vault Door Training",
        platform: "picoCTF",
        category: "reversing",
        difficulty: "beginner",
        points: 50,
        views: 9876,
        description: "Introduction to reverse engineering with Java code.",
        solution: "Read and understand the provided Java source code to extract the password that becomes the flag.",
        steps: [
            "Download and open the Java source file",
            "Locate the password checking function",
            "Read the character-by-character comparison",
            "Reconstruct the password from the source",
            "Format as flag: picoCTF{password}"
        ],
        tools: ["Text editor", "Java compiler (optional)"],
        learningPoints: "Code reading, understanding comparison logic, basic reverse engineering"
    },
    {
        id: 6,
        title: "Buffer Overflow 0",
        platform: "picoCTF",
        category: "pwn",
        difficulty: "intermediate",
        points: 100,
        views: 7654,
        description: "Introduction to buffer overflow vulnerabilities.",
        solution: "Overflow the buffer to overwrite the return address and execute the win function.",
        steps: [
            "Analyze the provided C source code",
            "Identify the vulnerable gets() or strcpy() function",
            "Calculate buffer size and overflow amount needed",
            "Create payload with padding + target address",
            "Send payload to the remote server"
        ],
        tools: ["gdb", "pwntools", "Python"],
        learningPoints: "Buffer overflow basics, stack layout, exploit development"
    },
    {
        id: 7,
        title: "XSS Challenge",
        platform: "Google CTF",
        category: "web",
        difficulty: "advanced",
        points: 500,
        views: 5432,
        description: "Complex XSS exploitation with CSP bypass.",
        solution: "Chain multiple XSS vectors to bypass Content Security Policy and steal admin cookies.",
        steps: [
            "Identify XSS injection point in the application",
            "Analyze CSP headers to find allowed sources",
            "Use JSONP endpoint for CSP bypass",
            "Craft payload to exfiltrate cookies",
            "Set up webhook to receive stolen data"
        ],
        tools: ["Burp Suite", "Browser DevTools", "Request Bin"],
        learningPoints: "Advanced XSS, CSP bypass techniques, DOM manipulation"
    },
    {
        id: 8,
        title: "Shark on Wire",
        platform: "picoCTF",
        category: "forensics",
        difficulty: "intermediate",
        points: 150,
        views: 8123,
        description: "Network traffic analysis using Wireshark.",
        solution: "Analyze PCAP file to find UDP stream containing the flag transmitted across the network.",
        steps: [
            "Open the PCAP file in Wireshark",
            "Filter for UDP traffic: udp",
            "Follow UDP streams one by one",
            "Look for ASCII data that resembles flag format",
            "Alternatively, use: strings capture.pcap | grep pico"
        ],
        tools: ["Wireshark", "tshark", "NetworkMiner"],
        learningPoints: "Network forensics, protocol analysis, traffic inspection"
    },
    {
        id: 9,
        title: "RSA Pop Quiz",
        platform: "picoCTF",
        category: "crypto",
        difficulty: "advanced",
        points: 300,
        views: 4567,
        description: "Interactive RSA cryptography challenge.",
        solution: "Answer a series of RSA-related questions by computing various cryptographic values.",
        steps: [
            "Connect to the challenge server",
            "For each question, compute the required RSA value",
            "Use Python with gmpy2 or sympy for large number operations",
            "Common questions: compute d from e,n,p,q or decrypt ciphertext",
            "Automate with pwntools for speed"
        ],
        tools: ["Python", "gmpy2", "pwntools", "RsaCtfTool"],
        learningPoints: "RSA mathematics, modular arithmetic, cryptographic implementations"
    },
    {
        id: 10,
        title: "Assembly Required",
        platform: "picoCTF",
        category: "reversing",
        difficulty: "intermediate",
        points: 250,
        views: 6789,
        description: "WebAssembly reverse engineering challenge.",
        solution: "Decompile WebAssembly to understand the logic and find the correct input that produces the flag.",
        steps: [
            "Download the .wasm file from the website",
            "Use wasm2wat or online decompiler to convert to readable format",
            "Analyze the comparison logic and hash functions",
            "Reverse the algorithm or brute force possible inputs",
            "Input the correct value to get the flag"
        ],
        tools: ["wasm2wat", "wabt tools", "Browser DevTools"],
        learningPoints: "WebAssembly structure, decompilation, algorithm analysis"
    },
    {
        id: 11,
        title: "John Pollard",
        platform: "picoCTF",
        category: "crypto",
        difficulty: "beginner",
        points: 75,
        views: 10234,
        description: "RSA with small factors - prime factorization challenge.",
        solution: "Factor the given RSA modulus n into primes p and q, then decrypt the message.",
        steps: [
            "Receive n (modulus) and e (public exponent)",
            "Use factordb.com to factor n into p and q",
            "Calculate phi = (p-1)(q-1)",
            "Calculate d = inverse(e, phi)",
            "Decrypt: message = pow(ciphertext, d, n)"
        ],
        tools: ["Python", "factordb.com", "RsaCtfTool"],
        learningPoints: "RSA weaknesses, factorization attacks, cryptographic implementation"
    },
    {
        id: 12,
        title: "Format String Bug",
        platform: "HackTheBox",
        category: "pwn",
        difficulty: "advanced",
        points: 400,
        views: 3456,
        description: "Exploit format string vulnerability to leak memory and gain control.",
        solution: "Use format string specifiers to leak addresses and write arbitrary values to memory.",
        steps: [
            "Identify printf vulnerability with user input",
            "Use %x to leak stack values and find offsets",
            "Locate target address (GOT entry or return address)",
            "Use %n to write to arbitrary memory location",
            "Overwrite with address of win function or shellcode"
        ],
        tools: ["gdb", "pwntools", "Python", "radare2"],
        learningPoints: "Format string vulnerabilities, memory exploitation, GOT overwrite"
    }
];

// State management
let currentWalkthroughs = [...walkthroughs];
let displayCount = 6;

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    renderWalkthroughs();
    setupEventListeners();
});

// Render walkthroughs to the grid
function renderWalkthroughs(walkthroughsToRender = currentWalkthroughs.slice(0, displayCount)) {
    const grid = document.getElementById('walkthroughGrid');
    grid.innerHTML = '';

    if (walkthroughsToRender.length === 0) {
        grid.innerHTML = '<p style="text-align: center; color: var(--text-secondary); grid-column: 1/-1;">No walkthroughs found matching your filters.</p>';
        return;
    }

    walkthroughsToRender.forEach(walkthrough => {
        const card = createWalkthroughCard(walkthrough);
        grid.appendChild(card);
    });

    // Update load more button visibility
    const loadMoreBtn = document.getElementById('loadMoreBtn');
    if (displayCount >= currentWalkthroughs.length) {
        loadMoreBtn.style.display = 'none';
    } else {
        loadMoreBtn.style.display = 'block';
    }
}

// Create walkthrough card element
function createWalkthroughCard(walkthrough) {
    const card = document.createElement('div');
    card.className = 'walkthrough-card';
    card.onclick = () => openModal(walkthrough);

    card.innerHTML = `
        <div class="card-header">
            <div class="card-title">${walkthrough.title}</div>
            <div class="card-platform">${walkthrough.platform}</div>
        </div>
        <div class="card-body">
            <div class="card-tags">
                <span class="tag tag-category">${walkthrough.category}</span>
                <span class="tag tag-difficulty tag-${walkthrough.difficulty}">${walkthrough.difficulty}</span>
            </div>
            <p class="card-description">${walkthrough.description}</p>
            <div class="card-footer">
                <span class="card-points">${walkthrough.points} points</span>
                <span class="card-views">👁 ${walkthrough.views.toLocaleString()} views</span>
            </div>
        </div>
    `;

    return card;
}

// Setup event listeners
function setupEventListeners() {
    // Filter listeners
    document.getElementById('ctfFilter').addEventListener('change', applyFilters);
    document.getElementById('categoryFilter').addEventListener('change', applyFilters);
    document.getElementById('difficultyFilter').addEventListener('change', applyFilters);
    document.getElementById('searchInput').addEventListener('input', applyFilters);
    document.querySelector('.search-btn').addEventListener('click', applyFilters);

    // Load more button
    document.getElementById('loadMoreBtn').addEventListener('click', loadMore);

    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = this.getAttribute('href').substring(1);
            scrollToSection(target);
            
            // Update active state
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });

    // Category cards
    document.querySelectorAll('.category-card').forEach(card => {
        card.addEventListener('click', function() {
            const category = this.getAttribute('data-category');
            document.getElementById('categoryFilter').value = category;
            applyFilters();
            scrollToSection('walkthroughs');
        });
    });

    // Mobile toggle
    document.getElementById('mobileToggle').addEventListener('click', function() {
        const navLinks = document.querySelector('.nav-links');
        navLinks.style.display = navLinks.style.display === 'flex' ? 'none' : 'flex';
    });

    // Modal close
    document.querySelector('.close-modal').addEventListener('click', closeModal);
    window.addEventListener('click', function(e) {
        const modal = document.getElementById('walkthroughModal');
        if (e.target === modal) {
            closeModal();
        }
    });
}

// Apply filters
function applyFilters() {
    const ctfFilter = document.getElementById('ctfFilter').value;
    const categoryFilter = document.getElementById('categoryFilter').value;
    const difficultyFilter = document.getElementById('difficultyFilter').value;
    const searchQuery = document.getElementById('searchInput').value.toLowerCase();

    currentWalkthroughs = walkthroughs.filter(w => {
        const matchesCTF = ctfFilter === 'all' || w.platform.toLowerCase().includes(ctfFilter);
        const matchesCategory = categoryFilter === 'all' || w.category === categoryFilter;
        const matchesDifficulty = difficultyFilter === 'all' || w.difficulty === difficultyFilter;
        const matchesSearch = searchQuery === '' || 
            w.title.toLowerCase().includes(searchQuery) ||
            w.description.toLowerCase().includes(searchQuery);

        return matchesCTF && matchesCategory && matchesDifficulty && matchesSearch;
    });

    displayCount = 6;
    renderWalkthroughs();
}

// Load more walkthroughs
function loadMore() {
    displayCount += 6;
    renderWalkthroughs();
}

// Scroll to section
function scrollToSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// Open modal with walkthrough details
function openModal(walkthrough) {
    const modal = document.getElementById('walkthroughModal');
    const modalBody = document.getElementById('modalBody');

    modalBody.innerHTML = `
        <h2>${walkthrough.title}</h2>
        <div class="modal-tags">
            <span class="tag tag-category">${walkthrough.category}</span>
            <span class="tag tag-difficulty tag-${walkthrough.difficulty}">${walkthrough.difficulty}</span>
            <span class="tag" style="background: rgba(236, 72, 153, 0.2); color: var(--accent-color);">${walkthrough.platform}</span>
            <span class="tag" style="background: rgba(16, 185, 129, 0.2); color: var(--success);">${walkthrough.points} points</span>
        </div>

        <div class="modal-section">
            <h3>📝 Challenge Description</h3>
            <p>${walkthrough.description}</p>
        </div>

        <div class="modal-section">
            <h3>💡 Solution Overview</h3>
            <p>${walkthrough.solution}</p>
        </div>

        <div class="modal-section">
            <h3>🔧 Step-by-Step Solution</h3>
            <ol style="margin-left: 1.5rem; line-height: 1.8;">
                ${walkthrough.steps.map(step => `<li>${step}</li>`).join('')}
            </ol>
        </div>

        <div class="modal-section">
            <h3>🛠️ Tools Used</h3>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                ${walkthrough.tools.map(tool => `
                    <span class="tag" style="background: rgba(139, 92, 246, 0.2); color: var(--secondary-color);">${tool}</span>
                `).join('')}
            </div>
        </div>

        <div class="modal-section">
            <h3>📚 Key Learning Points</h3>
            <p>${walkthrough.learningPoints}</p>
        </div>

        <div class="modal-section">
            <h3>💻 Example Code/Command</h3>
            <div class="code-block">
# Example for ${walkthrough.title}
${getExampleCode(walkthrough.category)}
            </div>
        </div>

        <div style="margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color); color: var(--text-muted); font-size: 0.9rem;">
            👁 ${walkthrough.views.toLocaleString()} views • ${walkthrough.points} points
        </div>
    `;

    modal.style.display = 'block';
}

// Close modal
function closeModal() {
    document.getElementById('walkthroughModal').style.display = 'none';
}

// Get example code based on category
function getExampleCode(category) {
    const examples = {
        web: `# Testing for SQL injection
' OR 1=1--
admin'/**/OR/**/1=1#

# Using sqlmap
sqlmap -u "http://target.com/page?id=1" --dbs`,
        crypto: `# Caesar cipher decryption
def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
    return result`,
        forensics: `# Extract strings from file
strings image.jpg | grep -i "flag"

# Check file metadata
exiftool image.jpg

# Analyze with binwalk
binwalk -e suspicious_file`,
        reversing: `# Disassemble with objdump
objdump -d binary_file

# Use GDB for debugging
gdb ./binary
break main
run
disassemble`,
        pwn: `# Buffer overflow exploit template
from pwn import *

p = process('./vuln_binary')
payload = b'A' * 64  # padding
payload += p64(0xdeadbeef)  # return address
p.sendline(payload)`,
        misc: `# Common useful commands
cat file.txt
strings binary
file unknown_file
xxd file.bin | head`
    };

    return examples[category] || '# Challenge-specific commands will vary';
}

// Add smooth scroll behavior
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});