import jsonwebtoken from "jsonwebtoken";
import { jwtVerify, importJWK, JWTHeaderParameters, JWTPayload } from "jose";

export interface JWTHeader {
    kid: string;
}

interface IVerifyTokenResponse {
    protectedHeader: JWTHeaderParameters;
    payload: JWTPayload;
}

export const verifyToken = async (
    token: string,
): Promise<IVerifyTokenResponse> => {
    const { header } = jsonwebtoken.decode(token, {
        complete: true,
    }) as jsonwebtoken.Jwt;
    const resp = await fetch(
        "https://dev.uniresolver.io/1.0/identifiers/" + header.kid,
        {
            method: "GET",
        },
    );
    const jwk = await importJWK(
        (
            await resp.json()
        ).didDocument.verificationMethod[0].publicKeyJwk,
    );

    const decoded = await jwtVerify(token, jwk);
    // console.log((await resp.json()).didDocument);
    return decoded;
};
