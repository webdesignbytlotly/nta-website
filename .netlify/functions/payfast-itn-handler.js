// .netlify/functions/payfast-itn-handler.js

const crypto = require('crypto');
const querystring = require('querystring');
const fetch = require('node-fetch');

// 🟢 STEP 1: READ SECRETS FROM NETLIFY ENVIRONMENT VARIABLES
// NOTE: You MUST set these environment variables in your Netlify Site Settings for this to work.
// 1. PAYFAST_PASSPHRASE: Onksyeoh12jdikla
// 2. FORMSPREE_ENDPOINT: https://formspree.io/f/mblzwyby
// 3. YOUR_SITE_BASE_URL: https://ntamoodels.co.za
const PAYFAST_PASSPHRASE = process.env.PAYFAST_PASSPHRASE; 
const FORMSPREE_ENDPOINT = process.env.FORMSPREE_ENDPOINT; 
const YOUR_SITE_BASE_URL = process.env.YOUR_SITE_BASE_URL;

// Public Payfast details (can be hardcoded)
const MERCHANT_ID = '30920829';
const MERCHANT_KEY = 'gqnzkfosq9fc8';
const PAYFAST_VERIFY_URL = 'https://www.payfast.co.za/eng/query/validate'; 

/**
 * Creates the security checksum string required by Payfast ITN.
 * This ensures the integrity of the data sent by Payfast.
 */
function createChecksum(data, passphrase) {
    const keys = Object.keys(data).sort();

    let pfParamString = '';
    for (const key of keys) {
        if (key !== 'signature') {
            const value = data[key];
            if (value !== 'true' && value !== 'false' && value !== '') {
                // IMPORTANT: Payfast encoding requires special handling for spaces ('+')
                pfParamString += `${key}=${encodeURIComponent(value.trim()).replace(/%20/g, '+')}&`;
            }
        }
    }

    pfParamString = pfParamString.slice(0, -1); // Remove the trailing '&'

    if (passphrase) {
        pfParamString += `&passphrase=${encodeURIComponent(passphrase).replace(/%20/g, '+')}`;
    }

    return crypto.createHash('md5').update(pfParamString).digest('hex');
}


exports.handler = async (event) => {
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    const payfastData = querystring.parse(event.body);
    const receivedSignature = payfastData.signature;
    const paymentStatus = payfastData.payment_status;
    const referenceId = payfastData.custom_str1;
    
    // Check for critical fields and secret integrity
    if (!receivedSignature || !referenceId || !PAYFAST_PASSPHRASE) {
        console.error('ITN ERROR: Missing critical configuration or data.');
        return { statusCode: 400, body: 'Missing required parameters.' };
    }

    // 1. Verify Checksum (Security Step 1)
    const calculatedChecksum = createChecksum(payfastData, PAYFAST_PASSPHRASE);

    if (calculatedChecksum !== receivedSignature) {
        console.error('ITN FAILURE: Checksum mismatch for Ref:', referenceId);
        return { statusCode: 400, body: 'ITN Signature mismatch.' };
    }

    // 2. Check for COMPLETE Payment Status
    if (paymentStatus !== 'COMPLETE') {
        console.warn(`ITN Warning: Payment status is ${paymentStatus}. Not processing form for Ref: ${referenceId}`);
        // Return 200 OK so Payfast stops sending notifications for pending/failed payments
        return { statusCode: 200, body: `Payment status ${paymentStatus} received.` };
    }

    // 3. Verify the Transaction with Payfast (Security Step 2: Server-to-Server Validation)
    try {
        const verificationResponse = await fetch(PAYFAST_VERIFY_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: event.body // Send the exact POST data back to Payfast for verification
        });

        const verificationResult = await verificationResponse.text();

        if (verificationResult !== 'VALID') {
            console.error('ITN FAILURE: Payfast verification failed. Response:', verificationResult, 'Ref:', referenceId);
            return { statusCode: 400, body: 'ITN Validation Failed.' };
        }
    } catch (error) {
        console.error('Payfast verification request failed:', error);
        return { statusCode: 500, body: 'Payfast Verification Server Error.' };
    }

    // 4. Prepare and Submit Data to Formspree
    // This version sends the securely validated payment confirmation data.
    const confirmedSubmissionData = {
        "_subject": `✅ New NTA Enrollment Application (Payment Confirmed - Ref: ${referenceId})`,
        "Transaction Status": paymentStatus,
        "Email": payfastData.email_address || 'N/A',
        "First Name": payfastData.name_first || 'N/A',
        "Last Name": payfastData.name_last || 'N/A',
        "Application Reference ID": referenceId,
        "Amount Paid": payfastData.amount_fee,
        "Payfast Transaction ID": payfastData.pf_payment_id,
        "Confirmation Time": new Date().toISOString()
    };

    try {
        const formspreeResponse = await fetch(FORMSPREE_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(confirmedSubmissionData)
        });

        if (formspreeResponse.ok) {
            console.log('Successfully submitted confirmed application to Formspree. Ref:', referenceId);
            return { statusCode: 200, body: 'ITN Processed. Formspree submission successful.' };
        } else {
            console.error('Formspree submission failed:', formspreeResponse.status, 'Ref:', referenceId);
            return { statusCode: 500, body: 'Formspree submission failed.' };
        }

    } catch (error) {
        console.error('Final Submission Error:', error);
        return { statusCode: 500, body: 'Final Submission Server Error.' };
    }
};
