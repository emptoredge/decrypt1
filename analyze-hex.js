// Analyze the RSA-decrypted hex data
const hexData = "a6e73319cb75ce39ed33b340484824878ac399c176d74e2e3975047b90bc31b8a72c6ffc5b2d7b9f";

console.log('🔍 Analyzing RSA-decrypted hex data...');
console.log(`📊 Hex: ${hexData}`);
console.log(`📊 Length: ${hexData.length / 2} bytes`);

const buffer = Buffer.from(hexData, 'hex');
console.log(`📊 Buffer: ${buffer.length} bytes`);

// Try different interpretations
console.log('\n🔧 Analysis attempts:');

// 1. Check if it's UTF-8 text
const utf8 = buffer.toString('utf8');
console.log(`📄 UTF-8: "${utf8}"`);
console.log(`📄 Is printable ASCII: ${/^[\x20-\x7E\s]*$/.test(utf8)}`);

// 2. Check each byte value
console.log('\n📊 Byte analysis:');
for (let i = 0; i < buffer.length; i++) {
  const byte = buffer[i];
  const char = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
  console.log(`  Byte ${i}: 0x${byte.toString(16).padStart(2, '0')} (${byte}) '${char}'`);
}

// 3. Look for patterns
console.log('\n🔍 Pattern analysis:');
console.log(`📊 First 4 bytes: ${buffer.subarray(0, 4).toString('hex')} (${Array.from(buffer.subarray(0, 4)).join(', ')})`);
console.log(`📊 Last 4 bytes: ${buffer.subarray(-4).toString('hex')} (${Array.from(buffer.subarray(-4)).join(', ')})`);

// 4. Check if it might be base64 encoded
try {
  const asBase64 = buffer.toString('base64');
  console.log(`📄 As Base64: ${asBase64}`);
  
  // Try decoding it as base64
  const base64Decoded = Buffer.from(asBase64, 'base64').toString('utf8');
  console.log(`📄 Base64 decoded: "${base64Decoded}"`);
} catch (e) {
  console.log('❌ Base64 conversion failed');
}

// 5. Check if it could be an integer or multiple integers
console.log('\n🔢 Numeric interpretation:');
if (buffer.length >= 4) {
  const uint32BE = buffer.readUInt32BE(0);
  const uint32LE = buffer.readUInt32LE(0);
  console.log(`📊 First 4 bytes as UInt32 (BE): ${uint32BE}`);
  console.log(`📊 First 4 bytes as UInt32 (LE): ${uint32LE}`);
}

// 6. Check if it could be compressed
try {
  const zlib = require('zlib');
  const inflated = zlib.inflateSync(buffer).toString('utf8');
  console.log(`📄 Inflated (deflate): "${inflated}"`);
} catch (e) {
  console.log('❌ Not deflate compressed');
}

try {
  const zlib = require('zlib');
  const gunzipped = zlib.gunzipSync(buffer).toString('utf8');
  console.log(`📄 Gunzipped: "${gunzipped}"`);
} catch (e) {
  console.log('❌ Not gzip compressed');
}

// 7. Check if it might be XOR encoded with a simple key
console.log('\n🔐 Simple XOR analysis:');
for (let key = 0; key < 256; key++) {
  const xored = Buffer.alloc(buffer.length);
  for (let i = 0; i < buffer.length; i++) {
    xored[i] = buffer[i] ^ key;
  }
  const xorText = xored.toString('utf8');
  
  // Check if it produces readable text
  if (/^[\x20-\x7E\s]*$/.test(xorText) && xorText.length > 10) {
    console.log(`🎯 XOR key ${key} (0x${key.toString(16)}): "${xorText}"`);
  }
}

// 8. Check if it's JSON with null bytes or other encoding
console.log('\n📄 JSON attempts:');
try {
  // Remove null bytes and try
  const cleanBuffer = buffer.filter(b => b !== 0);
  const cleanText = Buffer.from(cleanBuffer).toString('utf8');
  console.log(`📄 Without null bytes: "${cleanText}"`);
  
  const parsed = JSON.parse(cleanText);
  console.log('🎉 Valid JSON after cleaning:', parsed);
} catch (e) {
  console.log('❌ Not JSON even after cleaning');
}

console.log('\n📋 Summary:');
console.log('✅ Successfully RSA-decrypted 37 bytes of data');
console.log('❌ Data is not readable UTF-8 text');
console.log('❌ Data is not compressed (gzip/deflate)');
console.log('❌ Data is not simple XOR encoded');
console.log('💡 This might be:');
console.log('   - Binary protocol data (protobuf, etc.)');
console.log('   - Another layer of encryption');
console.log('   - Custom WhatsApp encoding scheme');
console.log('   - Raw binary data that needs specific interpretation');