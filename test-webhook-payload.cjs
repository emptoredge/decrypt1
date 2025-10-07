// Test the actual webhook payload you received
const crypto = require('crypto');
require('dotenv').config();

async function testWebhookPayload() {
    try {
        console.log('🔍 Testing actual webhook payload...');
        
        // Load private key from environment
        const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;
        if (!PRIVATE_KEY_PEM) {
            throw new Error('PRIVATE_KEY environment variable not found');
        }
        
        // Your actual payload data
        const body = {
            "encrypted_flow_data": "kv/Sw+MYASNfqCZLuFNK2PO0gmkyS95+RCQvZLOzS2a81hyj3qOKDUlATdmaHQNz7QyivTtzA++RBKoYXcERXcuGtXL5qvyejpmlcY1Vy0cMr3Aongc5EEpe+tteJJawmpQQrsgXdCHMxByQBiWQFRHp1cwOS88pyJy7+SVcNBJG3OPI9fQv",
            "encrypted_aes_key": "Km/VKUONTfIAZiRVbBJiZocHCew0DWrKDHyKsqu1e7vRDoT3uMBQgL6S1FH4B8MNBlCKchDcHPyhw1nAIvyTT/MwWH/X14lX7MePR4ornvKikIKodcPbsjwI42yhTBP8w+9S40qC/gei7YWpBrEM5+5DmSyfGqAlCZTxH/nw6hSPgzcYqBrRttLQkcu0CeyT0Km0WXtici1tx5a7Eq7iqFYxvFL1QlybaLXM7fje4iUSm6+Low+QgKmAO92CS3NrNMlGhTBnDNHjiPgILV4JE3Ak8e3tIMZouWqBpZeBXXodt8xKYllKTabYdubbFLBgPTCPDmynTllfv6/JABxlLw==",
            "initial_vector": "fVdNp8R+ccvx+ocXk2ac5g=="
        };

        // Step 1: Decrypt the AES key using RSA
        const encryptedAesKeyBuffer = Buffer.from(body.encrypted_aes_key, 'base64');
        const aesKey = crypto.privateDecrypt(
            {
                key: PRIVATE_KEY_PEM,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            encryptedAesKeyBuffer
        );
        
        console.log('✅ AES key decrypted successfully');
        console.log('🔑 AES key length:', aesKey.length, 'bytes');

        // Step 2: Prepare for AES decryption
        const encryptedData = Buffer.from(body.encrypted_flow_data, 'base64');
        const iv = Buffer.from(body.initial_vector, 'base64');
        
        console.log('📊 Encrypted data length:', encryptedData.length, 'bytes');
        console.log('🔢 IV length:', iv.length, 'bytes');

        // Step 3: Extract the tag and ciphertext
        const authTagLength = 16; // GCM auth tag is always 16 bytes
        const authTag = encryptedData.slice(-authTagLength);
        const ciphertext = encryptedData.slice(0, -authTagLength);
        
        console.log('🏷️  Auth tag length:', authTag.length, 'bytes');
        console.log('📄 Ciphertext length:', ciphertext.length, 'bytes');

        // Step 4: Decrypt using AES-128-GCM
        const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        const decryptedText = decrypted.toString('utf8');
        
        console.log('🎉 DECRYPTED SUCCESSFULLY!');
        
        // Parse the decrypted data
        const decryptedData = JSON.parse(decryptedText);
        
        console.log('📋 Action:', decryptedData.action);
        console.log('📋 Screen:', decryptedData.screen);
        console.log('📋 Version:', decryptedData.version);
        
        console.log('\n📱 DATA RECEIVED:');
        console.log(JSON.stringify(decryptedData.data, null, 2));
        
        // Check for mobile number
        if (decryptedData.data && decryptedData.data.mobile_number) {
            console.log('\n✅ MOBILE NUMBER FOUND:', decryptedData.data.mobile_number);
        } else {
            console.log('\n❌ Mobile number NOT found in form data');
            console.log('🔍 Available fields:', Object.keys(decryptedData.data || {}));
        }
        
        // Show form data capture
        const formData = {
            screen: decryptedData.screen,
            data: decryptedData.data,
            timestamp: new Date().toISOString()
        };
        
        console.log('\n📋 Form Data Captured:');
        console.log(JSON.stringify(formData, null, 2));
        
        // Show what would happen next (routing)
        const routingModel = {
            "FIRST_NAME": ["LAST_NAME"],
            "LAST_NAME": ["DATE_OF_BIRTH"],
            "DATE_OF_BIRTH": ["HEIGHT_CM"],
            "HEIGHT_CM": ["WEIGHT_KG"],
            "WEIGHT_KG": ["ALLERGIES"],
            // ... etc
        };
        
        const currentScreen = decryptedData.screen;
        const nextScreen = routingModel[currentScreen] ? routingModel[currentScreen][0] : 'UNKNOWN';
        
        console.log(`\n🧭 Navigation: ${currentScreen} → ${nextScreen}`);
        
        // Prepare response data
        const responseData = {
            screen: nextScreen,
            data: decryptedData.data // Carry forward all data
        };
        
        console.log('\n📋 Response being sent back:');
        console.log(JSON.stringify(responseData, null, 2));
        
        return {
            success: true,
            decryptedData,
            formData,
            responseData
        };
        
    } catch (error) {
        console.error('❌ ERROR:', error.message);
        console.error('📍 Stack:', error.stack);
        return { success: false, error: error.message };
    }
}

testWebhookPayload().catch(console.error);