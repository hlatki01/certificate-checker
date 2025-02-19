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
        keepExtensions: true
    });

    form.parse(req, async (err, fields, files) => {
        if (err) {
            console.error("Formidable parsing error:", err);
            return res.status(500).json({ error: "Error processing form data" });
        }

        console.log("Received Fields:", fields); // Debugging log
        console.log("Received Files:", files);   // Debugging log

        const { xLogin, xTransKey, country, secretKey } = fields;

        if (!secretKey) {
            return res.status(400).json({ error: "Missing secretKey in request body" });
        }

        const xDate = new Date().toISOString();
        const apiURL = `https://sandbox-cert.dlocal.com/payments-methods?country=${country}`;

        const payload = { country };
        const concatenatedData = `${xLogin}${xDate}${JSON.stringify(payload)}`;

        try {
            const hashBytes = require('crypto')
                .createHmac('sha256', secretKey.trim())
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
