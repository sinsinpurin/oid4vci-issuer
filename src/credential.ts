import BlockBaseVCTemplate from "./config/credential_template/BlockBaseVC.json";
import { getAccessToken } from "./auth/mattrAccessToken";
import fetch from "node-fetch";

const templates: any = {
    BlockBaseVC: BlockBaseVCTemplate,
};

export const credentialLoader = (id: string) => {
    return templates[id];
};

interface IGetSignedCredentialResponse {
    credential: any;
    id: string;
    issuanceDate: string;
}

export const getSignedCredential = async (
    credentialId: string,
    credentialSubjectParam?: any,
): Promise<IGetSignedCredentialResponse> => {
    let credentialPayload = credentialLoader(credentialId);
    credentialPayload["credentialSubject"] = {
        ...credentialPayload["credentialSubject"],
        ...credentialSubjectParam["credentialSubject"],
    };
    const { access_token, token_type } = await getAccessToken();
    const resp = await fetch(
        `${process.env.MATTR_TENANT_URL}/v2/credentials/web-semantic/sign`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `${token_type} ${access_token}`,
            },
            body: JSON.stringify({
                payload: credentialPayload,
            }),
        },
    );
    const credential =
        await (resp.json() as Promise<IGetSignedCredentialResponse>);
    console.log(credential);
    return credential;
};
