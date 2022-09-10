const express = require('express');
// require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require("crypto");
const fs = require('fs');

const app = express();
app.use(express.json({limit: "50mb"}));
app.use(cors());

const algorithm = "RS256";
const issuer = "5121ce91-4a8f-4d3a-81a9-2b21039295aa";
const audience = "da2b9d46-de76-498e-8746-471e8dd3d120";
const subject = "api-request";
const privateKey = fs.readFileSync("./private_key.txt");

function calculateHash(body) {
    var buf = new Buffer.from(JSON.stringify(body));
    return crypto.createHash("sha256").update(buf).digest("base64");
}

function createToken(privateKey, requestBody) {
    var payload = {
        iss: issuer,
        aud: audience,
        sub: subject,
        rbh: calculateHash(requestBody)
    };

    return jwt.sign(payload, privateKey, {algorithm: algorithm, expiresIn: "1m", noTimestamp: true});
}

const start = async () => {
    try {
        app.post('/api/generateToken', async (req, res) => {
            try {
                const body = req.body;
                const token = createToken(privateKey, body);

                res.status(200).json({
                    "access_token": token,
                    "expires_in": "60"
                });
            } catch (err) {
                console.log(err);
                res.sendStatus(400);
            }
        });


        app.listen(process.env.PORT || 80, () => console.log("server launched"));
    } catch (err) {
        console.log(err);
    }
}

start();