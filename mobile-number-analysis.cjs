// Complete analysis of WhatsApp Flow mobile number handling
const crypto = require('crypto');
require('dotenv').config();

console.log('📊 WHATSAPP FLOW MOBILE NUMBER ANALYSIS');
console.log('=' .repeat(50));

console.log('\n🔍 FINDINGS FROM YOUR ACTUAL WEBHOOK:');
console.log('✅ Screen: FIRST_NAME');
console.log('✅ Data: {"first_name": "Kshitij "}');
console.log('❌ Mobile number: NOT included in form data');

console.log('\n📱 HOW WHATSAPP FLOWS HANDLE MOBILE NUMBERS:');
console.log('1. Mobile numbers are NOT automatically included in form submissions');
console.log('2. Mobile numbers come from the user\'s WhatsApp profile context');
console.log('3. You need to capture it from the webhook headers or initial flow context');

console.log('\n🔧 SOLUTIONS FOR MOBILE NUMBER CAPTURE:');

console.log('\n💡 OPTION 1: Extract from webhook headers');
console.log('   - WhatsApp sends user context in headers');
console.log('   - Look for X-WhatsApp-* headers or user context');

console.log('\n💡 OPTION 2: Modify flow.json to collect mobile number');
console.log('   - Add a phone input field in your flow');
console.log('   - Let users enter their mobile number manually');

console.log('\n💡 OPTION 3: Use WhatsApp Business API context');
console.log('   - Query WhatsApp Business API for user details');
console.log('   - Match by sender ID from webhook');

console.log('\n🔧 RECOMMENDED SOLUTION:');
console.log('Update your API to extract mobile number from webhook context');

console.log('\n📋 YOUR CURRENT n8n ENDPOINT RETURNS:');
const sampleN8nResponse = {
    encryptedResponse: "[Base64 encrypted response for WhatsApp]",
    formData: {
        screen: "FIRST_NAME",
        data: {
            first_name: "Kshitij "
        },
        timestamp: new Date().toISOString(),
        userPhone: "NOT_AVAILABLE" // ← This is the issue
    },
    decryptedRequest: {
        action: "data_exchange",
        screen: "FIRST_NAME", 
        data: {
            first_name: "Kshitij "
        },
        version: "3.0"
    },
    responseData: {
        screen: "LAST_NAME",
        data: {
            first_name: "Kshitij "
        }
    }
};

console.log(JSON.stringify(sampleN8nResponse, null, 2));

console.log('\n🎯 NEXT STEPS:');
console.log('1. Check the webhook headers for user context');
console.log('2. Update your API to extract mobile number from headers');
console.log('3. Include mobile number in the n8n response');
console.log('4. Test with the updated endpoint');

console.log('\n🔍 Let\'s check what headers were sent with your webhook...');