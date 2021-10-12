import * as core from '@actions/core';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

async function requestToken(clientId: string, clientSecret: string, refreshToken: string) {
    console.log('=== Requesting token ===');
    console.log('Making call to request token...');

    const endpoint = `https://accounts.google.com/o/oauth2/token`;

    let body = {
        client_id: clientId,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        redirect_uri: 'urn:ietf:wg:oauth:2.0:oob'
    };

    if (clientSecret !== undefined && clientSecret !== null && clientSecret !== '') {
        (body as any).client_secret = clientSecret;
    }

    const response = await axios.post(endpoint, body);

    console.log(`Response: ${JSON.stringify(response.data)}`);
    console.log('=== Requesting token finished ===');

    return response.data.access_token;
}

async function createAddon(zipPath: string, token: string) {
    console.log('=== Creating addon ===');

    const endpoint = `https://www.googleapis.com/upload/chromewebstore/v1.1/items?uploadType=media`;

    console.log('Reading zip file...');
    const body = fs.readFileSync(path.resolve(zipPath));

    console.log('Uploading zip file...');
    const response = await axios.post(endpoint, body, {
        headers: {
            Authorization: `Bearer ${token}`,
            'x-goog-api-version': '2'
        },
        maxContentLength: Infinity
    });
    console.log(`Response: ${JSON.stringify(response.data)}`);
    console.log('=== Creating addon finished ===');
}

async function updateAddon(appId: string, zip: string, token: string) {
    console.log('=== Updating addon ===');

    const endpoint = `https://www.googleapis.com/upload/chromewebstore/v1.1/items/${appId}?uploadType=media`;

    console.log('Reading zip file...');
    const body = fs.readFileSync(path.resolve(zip));

    console.log('Uploading zip file...');
    const response = await axios.put(endpoint, body, {
        headers: {
            Authorization: `Bearer ${token}`,
            'x-goog-api-version': '2'
        },
        maxContentLength: Infinity
    });

    console.log(`Response: ${JSON.stringify(response.data)}`);
    console.log('=== Updating addon finished ===');
}

async function publishAddon(appId: string, token: string, publishTarget: string) {
    console.log('=== Publishing addon ===');

    const endpoint = `https://www.googleapis.com/chromewebstore/v1.1/items/${appId}/publish?publishTarget=${publishTarget}`;

    console.log('Making call to update addon...');
    const response = await axios.post(
        endpoint,
        { target: publishTarget },
        {
            headers: {
                Authorization: `Bearer ${token}`,
                'x-goog-api-version': '2'
            }
        }
    );
    
    console.log(`Response: ${JSON.stringify(response.data)}`);
    console.log('=== Publishing addon finished ===');
}

async function run() {
    console.log('= Start cpcolella/chrome-adddon action =');
    console.log('Reading environment variables...');

    try {
        const clientId = core.getInput('client-id', { required: true });
        const refreshToken = core.getInput('refresh-token', { required: true });
        const zipPath = core.getInput('zip-path', { required: true });
        const clientSecret = core.getInput('client-secret');
        const extensionId = core.getInput('extension-id');
        let publishTarget = core.getInput('publish-target');

        if (!publishTarget) {
            publishTarget = 'default';
        }

        const token = await requestToken(clientId, clientSecret, refreshToken);
        console.log(`Token: ${token}`);

        if (extensionId && extensionId.length > 0) {
            await updateAddon(extensionId, zipPath, token);
            await publishAddon(extensionId, token, publishTarget);
        } else {
            await createAddon(zipPath, token);
            await publishAddon(extensionId, token, publishTarget);
        }
    } catch (error) {
        core.setFailed((error as Error).message);
        console.log('= Fail cpcolella/chrome-adddon action =');
    }
}

run();
