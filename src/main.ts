import * as core from '@actions/core';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

async function requestToken(id: string, secret: string, refresh: string) {
    console.log('=== Requesting token ===');
    console.log('Making call to request token...');

    const endpoint = `https://accounts.google.com/o/oauth2/token`;

    const response = await axios.get(endpoint, {
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        data: {
            client_id: id,
            client_secret: secret,
            code: refresh,
            grant_type: 'authorization_code',
            redirect_uri: 'urn:ietf:wg:oauth:2.0:oob'
        },
    });

    console.log(`Response: ${JSON.stringify(response.data)}`);
    console.log('=== Requesting token finished ===');

    return response.data.access_token;
}

async function createAddon(zip: string, token: string) {
    console.log('=== Creating addon ===');

    const endpoint = `https://www.googleapis.com/upload/chromewebstore/v1.1/items?uploadType=media`;

    console.log('Reading zip file...');
    const body = fs.readFileSync(path.resolve(zip));

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

async function updateAddon(id: string, zip: string, token: string) {
    console.log('=== Updating addon ===');

    const endpoint = `https://www.googleapis.com/upload/chromewebstore/v1.1/items/${id}?uploadType=media`;

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

async function publishAddon(id: string, token: string, publishTarget: string) {
    console.log('=== Publishing addon ===');

    const endpoint = `https://www.googleapis.com/chromewebstore/v1.1/items/${id}/publish`;

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
        const clientSecret = core.getInput('client-secret', { required: true });
        const refresh = core.getInput('refresh-token', { required: true });
        const zip = core.getInput('zip', { required: true });
        const extension = core.getInput('extension');
        const publishTarget = core.getInput('publish-target');

        const token = await requestToken(clientId, clientSecret, refresh);
        console.log(`Token: ${token}`);

        if (extension && extension.length > 0) {
            await updateAddon(extension, zip, token);
            await publishAddon(extension, token, publishTarget);
        } else {
            await createAddon(zip, token);
            await publishAddon(extension, token, publishTarget);
        }
    } catch (error) {
        core.setFailed(error.message);
        console.log(error);
        console.log('= Fail cpcolella/chrome-adddon action =');
    }
}

run();
