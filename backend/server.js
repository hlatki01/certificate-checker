const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');
const axios = require('axios');
const cors = require('cors');
const formidable = require('formidable');

const app = express();
app.use(cors());

// Serve static files from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

app.post('/proxy-request', async (req, res) => {
    const form = new formidable.IncomingForm({
        uploadDir: path.join(__dirname, 'certs'),
        keepExtensions: true,
        multiples: true,
    });

    form.parse(req, async (err, fields, files) => {
        if (err) {
            console.error("Formidable parsing error:", err);
            return res.status(500).json({ error: "Error processing form data" });
        }

        console.log("Received Fields:", fields); // Debugging log
        console.log("Received Files:", files);   // Debugging log

        // Extract text fields properly
        const xLogin = fields.xLogin && fields.xLogin.length > 0 ? fields.xLogin[0] : null;
        const xTransKey = fields.xTransKey && fields.xTransKey.length > 0 ? fields.xTransKey[0] : null;
        const country = fields.country && fields.country.length > 0 ? fields.country[0] : null;
        const secretKey = fields.secretKey && fields.secretKey.length > 0 ? fields.secretKey[0] : null;

        if (!xLogin || !xTransKey || !country || !secretKey) {
            return res.status(400).json({ error: "Missing required fields in request body" });
        }

        const xDate = new Date().toISOString();
        const apiURL = `https://sandbox-cert.dlocal.com/payments-methods?country=${country}`;

        const payload = { country };
        const concatenatedData = `${xLogin}${xDate}${JSON.stringify(payload)}`;

        try {
            const hashBytes = require('crypto')
                .createHmac('sha256', secretKey.trim()) // Ensure key is trimmed
                .update(concatenatedData)
                .digest('hex');

            const headers = {
                'X-Date': xDate,
                'X-Login': xLogin,
                'X-Trans-Key': xTransKey,
                'Authorization': `V2-HMAC-SHA256, Signature: ${hashBytes}`
            };

            res.json({ message: "Signature generated successfully", headers });

        } catch (error) {
            console.error("Error generating signature:", error);
            res.status(500).json({ error: error.message });
        }
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
