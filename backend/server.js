const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const https = require('https');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static files from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve "index.html" when accessing "/"
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Setup file upload using multer
const upload = multer({ dest: 'certs/' });

app.post('/proxy-request', upload.fields([
    { name: 'privateKeyFile', maxCount: 1 },
    { name: 'certificateFile', maxCount: 1 }
]), async (req, res) => {
    const { xLogin, xTransKey, country, secretKey } = req.body;
    const xDate = new Date().toISOString();
    const apiURL = `https://sandbox-cert.dlocal.com/payments-methods?country=${country}`;

    const payload = { country };
    const concatenatedData = `${xLogin}${xDate}${JSON.stringify(payload)}`;
    const hashBytes = require('crypto')
        .createHmac('sha256', secretKey)
        .update(concatenatedData)
        .digest('hex');

    const headers = {
        'X-Date': xDate,
        'X-Login': xLogin,
        'X-Trans-Key': xTransKey,
        'Authorization': `V2-HMAC-SHA256, Signature: ${hashBytes}`
    };

    try {
        const httpsAgent = new https.Agent({
            cert: fs.readFileSync(req.files['certificateFile'][0].path),
            key: fs.readFileSync(req.files['privateKeyFile'][0].path),
            rejectUnauthorized: false
        });

        const response = await axios.get(apiURL, { headers, httpsAgent });

        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    } finally {
        fs.unlinkSync(req.files['privateKeyFile'][0].path);
        fs.unlinkSync(req.files['certificateFile'][0].path);
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
