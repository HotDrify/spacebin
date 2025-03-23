<div align="center">
    <h1>🗑️ SpaceBin</h1>
    <p>A simple and elegant XOR-based encryption and decryption tool that converts text into a space-and-tab formatted ciphertext. Perfect for lightweight data obfuscation with optional salt and integrity checks.</p>
</div>

<h2>✨ Features</h2>
<li><b>Encryption</b>: Encrypts plaintext using XOR with a provided key and optional salt.</li>
<li><b>Decryption</b>: Decrypts ciphertext back to the original plaintext.</li>
<li><b>Space-Tab Format</b>: Outputs ciphertext as a sequence of spaces and tabs for subtle obfuscation.</li>
<li><b>Integrity Check</b>: Ensures data integrity during decryption using CRC32 checksum.</li>

<h2>📦 Build</h2>
build new <b>release binary</b>: <br>
<code>cargo build --release</code></br>