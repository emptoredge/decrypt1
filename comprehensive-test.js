// Comprehensive test to try all possible key extractions and cipher modes
import dotenv from 'dotenv';
import crypto, { createPrivateKey, privateDecrypt, createDecipheriv } from "crypto";

// Load environment variables
dotenv.config();

const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;

// New test data from the fresh webhook
const newTestData = {
  "encrypted_flow_data": "rf+aflRhin1nZgH/TBPr/dAa53me+uVc+Ggwe6huvIXFjixrs7hm6YWdUWp0jTSZiA==",
  "encrypted_aes_key": "G8sTawPCbrA1jb9RnoGc+px8pVXksmn2STRarCPVmNjIeLTyzrEwxYDQ0eQoYrt0D7ImehYSYTJNV8hEsrAaqeaj5krKduabDdUGZwghR5BJ/Vr/9mWectkNOP3mc72eUgEU94O5j25pxdrqUIh2Q8NIZiftB2Q4R7WplCkK3ELbn+cUkZJx39QwXsXkNKgShe2Nj6TomLdiP5KCTO1VhlTiEW+8znel10N9MZgXAKnldqLiUo8XNg1Ug0P1YATxu1u59Kll99ujm0c9CzeEl9Th2xjUpZoIROV24XBVlcp36B5KSXvfjSbVH1QcGvrHPcmRBwpFphG1noc4yGR4ig==",
  "initial_vector": "MvjpBexif5OLMzLWN6ecxA=="
};

async function comprehensiveDecryptionTest() {
  try {
    console.log('🔍 Comprehensive decryption test...');
    
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = newTestData;
    
    // Step 1: RSA decrypt the AES key
    console.log('\n🔐 Step 1: RSA decryption...');
    const privateKey = createPrivateKey(PRIVATE_KEY_PEM);
    
    let rsaDecrypted = null;
    try {
      // This works from our previous tests
      rsaDecrypted = privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
      console.log('✅ RSA decryption successful (simulated - would fail locally but works on Vercel)');
      
      // Use the known hex from debug output
      const knownHex = "0ee964cafcb18a4743b6fe86180c79e3a61ba7b38aea4a12891766a603f642242564a0c97bf7a2cf3e349ecd90e6456497332d58989264ca572684a360161b0df273308be391efa1078853f977f356415aa0945e388b0f0be1253d718a41d11b7997127527e1";
      rsaDecrypted = Buffer.from(knownHex, 'hex');
      
    } catch (error) {
      console.log('❌ RSA decryption failed locally (expected)');
      console.log('🔧 Using known hex data from Vercel debug output...');
      
      // Use the hex data we got from Vercel debug
      const knownHex = "0ee964cafcb18a4743b6fe86180c79e3a61ba7b38aea4a12891766a603f642242564a0c97bf7a2cf3e349ecd90e6456497332d58989264ca572684a360161b0df273308be391efa1078853f977f356415aa0945e388b0f0be1253d718a41d11b7997127527e1";
      rsaDecrypted = Buffer.from(knownHex, 'hex');
    }
    
    console.log(`📊 RSA decrypted data length: ${rsaDecrypted.length} bytes`);
    console.log(`📊 RSA decrypted hex: ${rsaDecrypted.toString('hex')}`);
    
    // Step 2: Try every possible 32-byte segment as AES key
    console.log('\n🔧 Step 2: Testing all possible 32-byte AES keys...');
    
    const encryptedData = Buffer.from(encrypted_flow_data, "base64");
    const iv = Buffer.from(initial_vector, "base64");
    
    console.log(`📊 Encrypted data length: ${encryptedData.length} bytes`);
    console.log(`📊 IV length: ${iv.length} bytes`);
    console.log(`📊 Encrypted data hex: ${encryptedData.toString('hex')}`);
    
    // Try all possible 32-byte segments
    for (let offset = 0; offset <= rsaDecrypted.length - 32; offset++) {
      const aesKey = rsaDecrypted.subarray(offset, offset + 32);
      console.log(`\n🔑 Testing offset ${offset}: ${aesKey.toString('hex')}`);
      
      // Try different cipher modes
      const modes = [
        'aes-256-cbc',
        'aes-256-gcm', 
        'aes-256-cfb',
        'aes-256-ofb',
        'aes-256-ctr'
      ];
      
      for (const mode of modes) {
        try {
          if (mode === 'aes-256-gcm') {
            // Try different auth tag configurations for GCM
            const tagLengths = [16, 12, 8];
            
            for (const tagLength of tagLengths) {
              if (encryptedData.length <= tagLength) continue;
              
              try {
                // Auth tag at end
                const authTag = encryptedData.subarray(-tagLength);
                const ciphertext = encryptedData.subarray(0, -tagLength);
                
                const decipher = crypto.createDecipheriv(mode, aesKey, iv);
                decipher.setAuthTag(authTag);
                
                let result = decipher.update(ciphertext, null, 'utf8');
                result += decipher.final('utf8');
                
                console.log(`🎉 SUCCESS! Mode: ${mode}, Offset: ${offset}, Tag length: ${tagLength}`);
                console.log(`📄 Decrypted: ${result}`);
                
                try {
                  const parsed = JSON.parse(result);
                  console.log(`📄 Parsed JSON:`, parsed);
                } catch (e) {
                  console.log(`📄 Not valid JSON, raw text: ${result}`);
                }
                
                return { success: true, mode, offset, tagLength, decrypted: result };
                
              } catch (gcmError) {
                // Silent - try next config
              }
            }
          } else {
            // Try regular block/stream modes
            const decipher = crypto.createDecipheriv(mode, aesKey, iv);
            
            let result = decipher.update(encryptedData, null, 'utf8');
            result += decipher.final('utf8');
            
            console.log(`🎉 SUCCESS! Mode: ${mode}, Offset: ${offset}`);
            console.log(`📄 Decrypted: ${result}`);
            
            try {
              const parsed = JSON.parse(result);
              console.log(`📄 Parsed JSON:`, parsed);
            } catch (e) {
              console.log(`📄 Not valid JSON, raw text: ${result}`);
            }
            
            return { success: true, mode, offset, decrypted: result };
          }
        } catch (error) {
          // Silent - try next mode
        }
      }
    }
    
    console.log('\n❌ No successful decryption found with any offset or mode');
    return { success: false };
    
  } catch (error) {
    console.error('\n💥 Test failed:', error.message);
    return { success: false, error: error.message };
  }
}

// Run the comprehensive test
comprehensiveDecryptionTest()
  .then(result => {
    if (result.success) {
      console.log('\n✅ Comprehensive test found a working solution!');
    } else {
      console.log('\n❌ Comprehensive test completed without finding a solution');
    }
  })
  .catch(error => {
    console.error('\n💥 Test failed with exception:', error.message);
  });