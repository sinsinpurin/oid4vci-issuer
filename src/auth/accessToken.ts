import { randomBytes } from "crypto";

export const createAccessToken = () => {
    return randomBytes(32).toString("hex");
};
