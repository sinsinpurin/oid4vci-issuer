import { randomUUID } from "crypto";
import NodeCache from "node-cache";

const Cache = new NodeCache();

export const createSession = (initParam: any) => {
    const sessionID = randomUUID();
    Cache.set(sessionID, initParam);
    return sessionID;
};

export const addSessionData = (sessionID: any, data: any) => {
    const sessionData = Cache.get(sessionID) as any;
    console.log(sessionData);
    Cache.set(sessionID, { ...sessionData, ...data });
};

export const getSession = (sessionID: any) => {
    console.log(Cache.get(sessionID));

    return Cache.get(sessionID) as any;
};
