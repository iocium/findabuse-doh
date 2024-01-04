import { Router } from 'itty-router';
import { Buffer } from 'node:buffer';
import validator from 'validator';
import dnsPacket from 'dns-packet';
import Package from '../package-lock.json';

export interface Env {}
const router = Router()

router.get('/dns-query', async (request, env, context) => {
    // First, grab some request information
	let url: any = new URL(request.url)

	// And grab the question
	let q: any = null;
	if (request.query.dns) {
		q = request.query.dns;
	}
	else {
		return new Response('Missing query in ?dns=', { status: 400 })
	}

	// Now, to validate the payload
	let t: any;
	try {
		t = Buffer.from(q, 'base64')
		t = dnsPacket.decode(t);
	}
	catch(e: any) {
		return new Response('Invalid query', { status: 400 })
	}

    let resp: any = {
        type: 'response',
        id: t.id,
        flags: dnsPacket.AUTHORITATIVE_ANSWER,
        answers: []
    }

    // Now, we know we only respond to TXT queries, anything else has no data
    if (t.type !== 'query') {
        return new Response(dnsPacket.encode(resp))
    }

    for (let q of t.questions) {
        if (q.type == 'TXT') {
            let subject: any = q.name.replaceAll('.abuse.email', '');

            if (validator.isIP(subject)) {
                // So now, we're going to fetch data
                let upstream: any = env.UPSTREAM || 'api.findabuse.email';
                let data: any = await fetch(`https://${upstream}/api/v1/${subject}`, {
                    cf: {
                        cacheTtl: 84600,
                        cacheEverything: true
                    }
                });
                data = await data.json();

                // Now, if we got a response, we return it
                if (data[subject].success) {
                    for (let addr of data[subject].contacts.abuse) {
                        resp.answers.push({
                            type: 'TXT',
                            class: 'IN',
                            name: q.name,
                            ttl: 300,
                            data: addr
                        })
                    }
                }
            }
        }
    }

    return new Response(dnsPacket.encode(resp), {
        headers: {
            'Content-Type': 'application/dns-message'
        }
    })
})

router.get('/', (request, env, context) => {
    return new Response(Package.version);
})

router.get('/', (request, env, context) => {
	let hostname: any = new URL(request.url).hostname
    return new Response(`Welcome to ${hostname}`);
})

router.all('*', () => new Response('Not Found.', { status: 404 }))

export default {
	fetch: router.handle
}