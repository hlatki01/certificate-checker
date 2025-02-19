const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const https = require('https');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Ensure form fields are parsed
app.use(cors());

// Serve static files from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// Setup file upload using Multer
const upload = multer({ dest: 'certs/' });

app.post('/proxy-request', upload.fields([
    { name: 'privateKeyFile', maxCount: 1 },
    { name: 'certificateFile', maxCount: 1 }
]), async (req, res) => {
    console.log("Received Request Body:", req.body); // Debugging log

    // Extract text fields from request
    const { xLogin, xTransKey, country, secretKey } = req.body;
    
    if (!secretKey) {
        return res.status(400).json({ error: "Missing secretKey in request body" });
    }

    const xDate = new Date().toISOString();
    const apiURL = `https://sandbox-cert.dlocal.com/payments-methods?country=${country}`;

    const payload = { country };
    const concatenatedData = `${xLogin}${xDate}${JSON.stringify(payload)}`;
    
    try {
        const hashBytes = require('crypto')
            .createHmac('sha256', secretKey.trim()) // Trim to remove accidental spaces
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
