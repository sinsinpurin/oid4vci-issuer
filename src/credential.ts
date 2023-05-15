import BlockBaseVCTemplate from "./config/credential_template/BlockBaseVC.json";
import { getAccessToken } from "./auth/mattrAccessToken";
import fetch from "node-fetch";

const templates: any = {
    BlockBaseVC: BlockBaseVCTemplate,
};

export const credentialLoader = (id: string, params?: any) => {
    return { ...templates[id], ...params };
};

interface IGetSignedCredentialResponse {
    credential: any;
    id: string;
    issuanceDate: string;
}

export const getSignedCredential = async (
    credentialId: string,
    param?: any,
): Promise<IGetSignedCredentialResponse> => {
    const credentialTemplate = credentialLoader(credentialId, param);
    const { access_token, token_type } = await getAccessToken();
    console.log(access_token);
    console.log(
        `${process.env.MATTR_TENANT_URL}/v2/credentials/web-semantic/sign`,
    );
    const resp = await fetch(
        `${process.env.MATTR_TENANT_URL}/v2/credentials/web-semantic/sign`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `${token_type} ${access_token}`,
            },
            body: JSON.stringify({
                payload: credentialTemplate,
            }),
        },
    );

    return await (resp.json() as Promise<IGetSignedCredentialResponse>);
};
