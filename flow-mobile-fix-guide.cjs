// WhatsApp Flow Mobile Number Fix Guide
console.log('📱 WHATSAPP FLOW MOBILE NUMBER ISSUE ANALYSIS');
console.log('=' .repeat(60));

console.log('\n✅ YOUR FLOW.JSON IS CORRECT!');
console.log('   Each screen includes mobile_number in data and payload');
console.log('   Expected format: "${data.mobile_number}"');

console.log('\n❌ THE PROBLEM:');
console.log('   WhatsApp is not providing mobile_number in the data context');
console.log('   Your webhook received: {"first_name": "Kshitij "}');
console.log('   Expected: {"first_name": "Kshitij ", "mobile_number": "15550001234"}');

console.log('\n🔧 SOLUTION:');
console.log('   The mobile number must be provided when you SEND the Flow to the user');
console.log('   via WhatsApp Business API, not when they submit it');

console.log('\n📋 WHATSAPP BUSINESS API FLOW MESSAGE FORMAT:');
const flowMessage = {
  "messaging_product": "whatsapp",
  "to": "15550001234", // User's phone number
  "type": "interactive",
  "interactive": {
    "type": "flow",
    "header": {
      "type": "text",
      "text": "Health Tracker Form"
    },
    "body": {
      "text": "Please fill out your health information"
    },
    "footer": {
      "text": "Secure and confidential"
    },
    "action": {
      "name": "flow",
      "parameters": {
        "flow_message_version": "3",
        "flow_token": "your_flow_token",
        "flow_id": "your_flow_id",
        "flow_cta": "Start Health Check",
        "flow_action": "navigate",
        "flow_action_payload": {
          "screen": "FIRST_NAME",
          "data": {
            "mobile_number": "15550001234" // ← PROVIDE IT HERE!
          }
        }
      }
    }
  }
};

console.log('\n🎯 CRITICAL STEP:');
console.log('When sending the Flow via WhatsApp Business API:');
console.log(JSON.stringify(flowMessage, null, 2));

console.log('\n📝 WHAT YOU NEED TO DO:');
console.log('1. Update your WhatsApp Business API call to include mobile_number in flow_action_payload.data');
console.log('2. The mobile_number should be the recipient\'s phone number (same as "to" field)');
console.log('3. WhatsApp will then carry this data through all screens');

console.log('\n✅ AFTER FIX:');
console.log('Your webhook will receive:');
console.log('{"first_name": "Kshitij ", "mobile_number": "15550001234"}');

console.log('\n🚀 ALTERNATIVE QUICK FIX:');
console.log('If you can\'t modify the Flow initialization, update your API to extract');
console.log('mobile number from webhook headers or other context.');