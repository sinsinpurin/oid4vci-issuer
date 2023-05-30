import express from "express";
import QRCode from "qrcode";
import oid4vciConfig from "./.well-known/openid-credential-issuer.json";
import sample from "./.well-known/sample.json";
import dotenv from "dotenv";
import { auth } from "express-oauth2-jwt-bearer";
import { getSignedCredential } from "./credential";
import { verifyToken, getDid } from "./jwt/verify";
import fetch from "node-fetch";
import { decode } from "jsonwebtoken";
import { createIssuerMetadata, createOffer } from "./ms";
import { addSessionData, createSession, getSession } from "./session";
import { createAccessToken } from "./auth/accessToken";
dotenv.config();

const app = express();

app.use(express.json());

app.get("/", (_, res) => {
    res.send("Hello world");
});

/**
 * This endpoint shows QR code
 */
app.get("/qr", async (_, res) => {
    try {
        const url = "openid-credential-offer://?credential_offer=";
        const offerRequest = {
            credential_issuer: process.env.ISSUER_ENDPOINT as string,
            credentials: ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
        };
        if (!url) {
            return res.status(400).send("URL query parameter is required");
        }
        const qrCodeImage = await QRCode.toDataURL(
            url + encodeURI(JSON.stringify(offerRequest)),
        );
        res.setHeader("Content-Type", "image/png");
        res.send(Buffer.from(qrCodeImage.split(",")[1], "base64"));
    } catch (err) {
        console.error(err);
        res.status(500).send("Error generating QR Code");
    }
    return undefined;
});

/** /.well-known/openid-credential-issuer
 * This endpoint is used by the wallet to get the configuration of the issuer.
 */
app.get("/.well-known/openid-credential-issuer", (_, res) => {
    res.json(oid4vciConfig);
});

app.get("/authorize", (req, res) => {
    const {
        scope,
        response_type,
        state,
        nonce,
        redirect_uri,
        code_challenge_method,
        code_challenge,
    } = req.query;
    const url = new URL(`https://dev-blockbase-mo.jp.auth0.com/authorize`);
    if (typeof scope === "string") url.searchParams.append("scope", scope);
    if (typeof response_type === "string")
        url.searchParams.append("response_type", response_type);
    if (typeof state === "string") url.searchParams.append("state", state);
    if (typeof nonce === "string") url.searchParams.append("nonce", nonce);
    if (typeof redirect_uri === "string")
        url.searchParams.append("redirect_uri", redirect_uri);
    if (typeof code_challenge_method === "string")
        url.searchParams.append("code_challenge_method", code_challenge_method);
    if (typeof code_challenge === "string")
        url.searchParams.append("code_challenge", code_challenge);

    // /.well-known/openid-credential-issuer から取れないデータはここで追加する
    const client_id = process.env.AUTH0_CLIENT_ID as string;
    url.searchParams.append("client_id", client_id);
    const prompt = "login";
    url.searchParams.append("prompt", prompt);

    const audience = process.env.ISSUER_ENDPOINT as string;
    url.searchParams.append("audience", audience);
    console.log(url.toString());
    res.redirect(url.toString());
    // res.redirect("https://google.com");
});

app.post("/token", async (req, res) => {
    const { grant_type, client_id, code_verifier, code, redirect_uri } =
        req.body;
    const url = new URL(`https://dev-blockbase-mo.jp.auth0.com/oauth/token`);

    const resp = await fetch(url.toString(), {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            grant_type,
            client_id,
            code_verifier,
            code,
            redirect_uri,
        }),
    });

    res.json(await resp.json());
});

const jwtCheck = auth({
    audience: process.env.ISSUER_ENDPOINT as string,
    issuerBaseURL: "https://dev-blockbase-mo.jp.auth0.com/",
    tokenSigningAlg: "RS256",
});

interface ICredentialRequest {
    format: string;
    proof: {
        proof_type: string;
        jwt: string;
    };
}

app.post("/credential", jwtCheck, async (req, res) => {
    const { format, proof } = req.body as ICredentialRequest;
    if (!format || !proof) {
        res.status(400).send("format or proof is missing");
    }
    //const { protectedHeader } = await verifyToken(proof.jwt);
    const did = getDid(proof.jwt);

    const { credential } = await getSignedCredential("BlockBaseVC", {
        credentialSubject: {
            id: did,
            name: "test",
        },
    });

    res.json({ credential, format });
});

// ms wrapper
app.get("/ms-qrcode", async (_, res) => {
    const request_uri =
        "https://verifiedid.did.msidentity.com/v1.0/tenants/b9a84eb8-a888-4f41-bb75-43447e36486a/verifiableCredentials/issuanceRequests/ece69722-2436-4e64-af74-7b56151e2352";
    const resp = await fetch(request_uri, {
        method: "GET",
    }).then((result) => result.text());

    const msIssueRequest = decode(resp);
    const { offer, sessionID } = createOffer(msIssueRequest);

    console.log(getSession(sessionID));
    console.log(offer);

    const url = "openid-credential-offer://?credential_offer=";
    const qrCodeImage = await QRCode.toDataURL(
        url + encodeURI(JSON.stringify(offer)),
    );

    res.setHeader("Content-Type", "image/png");
    res.send(Buffer.from(qrCodeImage.split(",")[1], "base64"));
});

// ms issuer metadata
app.get("/:id/.well-known/openid-credential-issuer", async (req, res) => {
    const { issueRequest } = getSession(req.params.id);

    const manifest_uri =
        issueRequest.claims.vp_token.presentation_definition
            .input_descriptors[0].issuance[0].manifest;
    const resp = await fetch(manifest_uri, {
        method: "GET",
    }).then((result) => result.json());

    const manifest = decode(resp.token);
    // add session
    addSessionData(req.params.id, { manifest });

    const issuerMetadata = createIssuerMetadata(
        req.params.id,
        issueRequest,
        manifest,
    );
    res.json(issuerMetadata);
});

// ms token endpoint
app.post("/:id/token", async (req, res) => {
    const { grant_type, client_id, code_verifier } = req.body;
    const req_pre_authorized_code = req.body["pre-authorized_code"];
    const { pre_authorized_code } = getSession(req.params.id);

    if (grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
        res.status(400).send("grant_type is invalid");
    }
    if (
        !pre_authorized_code ||
        pre_authorized_code != req_pre_authorized_code
    ) {
        res.status(400).send("pre-authorized_code is invalid");
    }
    const access_token = createAccessToken();

    // add session
    addSessionData(req.params.id, { access_token });

    res.json({
        access_token,
        scope: "ldp_vc:BlockBaseVC",
        expires_in: 86400,
        token_type: "Bearer",
    });
});

app.post("/credential", async (req, res) => {
    const { format, proof } = req.body as ICredentialRequest;
    const bearerHeader = req.headers["authorization"];
    const bearer = bearerHeader!.split(" ");
    const req_access_token = bearer[1];

    // access token check
    const { access_token } = getSession(req.params.id);
    if (!access_token || access_token != req_access_token) {
        res.status(400).send("access_token is missing");
    }

    const { manifest } = getSession(req.params.id);
    if (!format || !proof) {
        res.status(400).send("format or proof is missing");
    }

    const resp = await fetch(manifest.input.credentialIssuer, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: proof.jwt,
    }).then((result) => result.json());

    res.json(resp);
});

const port = process.env.PORT || 8000; // 環境変数からポートを取得し、存在しない場合は8000をデフォルトとします。

app.listen(port, () => console.log(`Server is running on port ${port}`));
