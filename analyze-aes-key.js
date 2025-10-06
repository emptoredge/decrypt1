// Deep analysis of the RSA-decrypted AES key structure
const aesKeyHex = "0ee964cafcb18a4743b6fe86180c79e3a61ba7b38aea4a12891766a603f642242564a0c97bf7a2cf3e349ecd90e6456497332d58989264ca572684a360161b0df273308be391efa1078853f977f356415aa0945e388b0f0be1253d718a41d11b7997127527e1";

console.log('🔍 Analyzing RSA-decrypted AES key structure...');
console.log(`📊 Total length: ${aesKeyHex.length / 2} bytes`);

const buffer = Buffer.from(aesKeyHex, 'hex');

// Look for patterns that might indicate structure
console.log('\n🔧 Structure analysis:');

// Check if it could be multiple keys or have metadata
console.log('📊 32-byte chunks:');
for (let i = 0; i < buffer.length; i += 32) {
  const chunk = buffer.subarray(i, Math.min(i + 32, buffer.length));
  console.log(`  Chunk ${Math.floor(i/32)}: ${chunk.toString('hex')} (${chunk.length} bytes)`);
}

console.log('\n📊 16-byte chunks:');
for (let i = 0; i < Math.min(64, buffer.length); i += 16) {
  const chunk = buffer.subarray(i, Math.min(i + 16, buffer.length));
  console.log(`  Chunk ${Math.floor(i/16)}: ${chunk.toString('hex')} (${chunk.length} bytes)`);
}

// Check for possible JSON or structured data
console.log('\n📄 Text interpretation attempts:');
try {
  const asText = buffer.toString('utf8');
  console.log(`📄 UTF-8: "${asText}"`);
  
  // Check if any part looks like JSON
  for (let i = 0; i < buffer.length - 10; i++) {
    const substr = buffer.subarray(i, Math.min(i + 50, buffer.length)).toString('utf8');
    if (substr.includes('{') || substr.includes('[')) {
      console.log(`📄 Possible JSON at offset ${i}: "${substr}"`);
    }
  }
} catch (e) {
  console.log('❌ UTF-8 conversion failed');
}

// Look for common key lengths
console.log('\n🔑 Common AES key length tests:');
const keyLengths = [16, 24, 32]; // AES-128, AES-192, AES-256

for (const keyLen of keyLengths) {
  if (buffer.length >= keyLen) {
    console.log(`📊 AES-${keyLen * 8} key from start: ${buffer.subarray(0, keyLen).toString('hex')}`);
    
    // Also try from different offsets
    for (let offset of [2, 4, 8, 16]) {
      if (buffer.length >= offset + keyLen) {
        console.log(`📊 AES-${keyLen * 8} key from offset ${offset}: ${buffer.subarray(offset, offset + keyLen).toString('hex')}`);
      }
    }
  }
}

// Check if the last part could be metadata
console.log('\n📊 End analysis:');
console.log(`📊 Last 32 bytes: ${buffer.subarray(-32).toString('hex')}`);
console.log(`📊 Last 16 bytes: ${buffer.subarray(-16).toString('hex')}`);
console.log(`📊 Last 8 bytes: ${buffer.subarray(-8).toString('hex')}`);

// Check if it could be a Base64 encoded structure
console.log('\n🔄 Base64 analysis:');
try {
  const asBase64 = buffer.toString('base64');
  console.log(`📄 As Base64: ${asBase64}`);
  
  // Try decoding parts as base64
  for (let len of [32, 44, 64]) {
    if (asBase64.length >= len) {
      try {
        const decoded = Buffer.from(asBase64.substring(0, len), 'base64');
        console.log(`📄 First ${len} chars as Base64: ${decoded.toString('hex')}`);
      } catch (e) {}
    }
  }
} catch (e) {
  console.log('❌ Base64 conversion failed');
}

console.log('\n💡 Summary:');
console.log('✅ RSA decryption produced 102 bytes');
console.log('🎯 Need to find the correct AES key within this data');
console.log('📝 The structure might contain:');
console.log('   - AES key (16/24/32 bytes)');
console.log('   - IV or nonce');
console.log('   - Authentication tag');
console.log('   - Metadata or padding');