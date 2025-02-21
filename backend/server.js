const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');
const axios = require('axios');
const cors = require('cors');
const formidable = require('formidable');

const app = express();
app.use(cors());

// Ensure certs directory exists
const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
}

// Serve static files from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

app.post('/proxy-request', async (req, res) => {
    const form = new formidable.IncomingForm({
        uploadDir: certsDir,
        keepExtensions: true,
        multiples: true
    });

    form.parse(req, async (err, fields, files) => {
        if (err) {
            console.error("Formidable parsing error:", err);
            return res.status(500).json({ error: "Error processing form data" });
        }

        console.log("Received Fields:", fields);
        console.log("Received Files:", files);

        // Extract text fields
        const xLogin = fields.xLogin ? fields.xLogin.toString() : null;
        const xTransKey = fields.xTransKey ? fields.xTransKey.toString() : null;
        const country = fields.country ? fields.country.toString() : null;
        const secretKey = fields.secretKey ? fields.secretKey.toString() : null;

        if (!xLogin || !xTransKey || !country || !secretKey) {
            return res.status(400).json({ error: "Missing required fields in request body" });
        }

        // Extract file paths
        const privateKeyPath = files.privateKeyFile ? files.privateKeyFile[0].filepath : null;
        const certificatePath = files.certificateFile ? files.certificateFile[0].filepath : null;

        if (!privateKeyPath || !certificatePath) {
            return res.status(400).json({ error: "Missing private key or certificate file" });
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

            // Create an HTTPS agent using the uploaded certificate and private key
            const httpsAgent = new https.Agent({
                key: fs.readFileSync(privateKeyPath),
                cert: fs.readFileSync(certificatePath),
                rejectUnauthorized: false // Set to true in production
            });

            // Call the dLocal API
            const response = await axios.get(apiURL, { headers, httpsAgent });
            console.log(response);
            

            res.json(response.data);
        } catch (error) {
            console.error("Error calling dLocal API:", error);
            res.status(500).json({ error: error.message });
        } finally {
            // Cleanup uploaded files after processing
            fs.unlinkSync(privateKeyPath);
            fs.unlinkSync(certificatePath);
        }
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
