import { randomBytes } from "crypto";
import { createSession } from "./session";

export const createOffer = (issueRequest: any) => {
    const pre_authorized_code = randomBytes(32).toString("hex");
    const sessionID = createSession({
        issueRequest,
        pre_authorized_code,
    });
    const offer = {
        credential_issuer:
            (process.env.ISSUER_ENDPOINT as string) + `/${sessionID}`,
        credentials: [
            {
                format: "jwt_vc_json",
                types: [
                    "VerifiableCredential",
                    issueRequest.claims.vp_token.presentation_definition
                        .input_descriptors[0].id,
                ],
            },
        ],
        grants: {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_authorized_code,
            },
            id_token_hint: {
                id_token_hint: issueRequest.id_token_hint,
            },
        },
    };
    return { sessionID, offer };
};

export const createIssuerMetadata = (
    sessionID: any,
    issuanceRequest: any,
    manifest: any,
) => {
    let credentialSubject = {};
    manifest.input.attestations.idTokens[0].claims.map((claim: any) => {
        credentialSubject = {
            ...credentialSubject,
            [claim.claim]: "",
        };
    });
    console.log(credentialSubject);
    const issuerMetadata = {
        issuer: process.env.ISSUER_ENDPOINT as string,
        credential_issuer:
            (process.env.ISSUER_ENDPOINT as string) +
            `/${sessionID}` +
            "/token",
        token_endpoint:
            (process.env.ISSUER_ENDPOINT as string) +
            `/${sessionID}` +
            "/token",
        scopes_supported: ["ldp_vc:BlockBaseVC"],
        response_types_supported: ["code"],
        grant_types_supported: [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ],
        token_endpoint_auth_methods_supported: ["none"],
        code_challenge_methods_supported: ["S256"],
        credential_endpoint:
            (process.env.ISSUER_ENDPOINT as string) +
            `/${sessionID}` +
            "/credential",
        credentials_supported: [
            {
                type: [
                    "VerifiableCredential",
                    issuanceRequest.claims.vp_token.presentation_definition
                        .input_descriptors[0].id,
                ],
                issuer: {
                    id: issuanceRequest.client_id,
                    name: issuanceRequest.registration.client_name,
                    logoUrl: issuanceRequest.registration.logo_uri,
                },
                name: manifest.display.card.title,
                description: manifest.display.card.description,
                credentialBranding: {
                    backgroundColor: manifest.display.card.backgroundColor,
                    watermarkImageUrl: manifest.display.card.logo.uri,
                },
                credentialSubject,
                "@context": ["https://www.w3.org/2018/credentials/v1"],
            },
        ],
    };
    return issuerMetadata;
};
