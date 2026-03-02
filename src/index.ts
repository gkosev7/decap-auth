import { OAuthClient } from './oauth';

interface Env {
	GITHUB_OAUTH_ID: string;
	GITHUB_OAUTH_SECRET: string;
  GITHUB_REPO_PRIVATE?: string;
}

function randomHex(bytes: number): string {
	const buf = new Uint8Array(bytes);
	crypto.getRandomValues(buf);
	return Array.from(buf)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

const createOAuth = (env: Env) => {
	return new OAuthClient({
		id: env.GITHUB_OAUTH_ID,
		secret: env.GITHUB_OAUTH_SECRET,
		target: {
			tokenHost: 'https://github.com',
			tokenPath: '/login/oauth/access_token',
			authorizePath: '/login/oauth/authorize',
		},
	});
};

const handleAuth = async (url: URL, env: Env) => {
  const repoIsPrivate =
    env.GITHUB_REPO_PRIVATE != undefined && env.GITHUB_REPO_PRIVATE !== '0';
  const repoScope = repoIsPrivate ? 'repo,user' : 'public_repo,user';

  const oauth2 = createOAuth(env);
  const authorizationUri = oauth2.authorizeURL({
    redirect_uri: `https://${url.hostname}/callback`,
    scope: repoScope,
    state: randomHex(16),
  });

  return new Response(null, {
    status: 302,
    headers: {
      location: authorizationUri,
      "Cache-Control": "no-store",
    },
  });
};


const callbackScriptResponse = (status: string, token: string) => {
  const tokenJson = JSON.stringify({ token });

  return new Response(
    `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
</head>
<body>
  <p>Authorizing Decap...</p>
  <script>
    (function () {
      var payload = 'authorization:github:${status}:' + ${JSON.stringify(tokenJson)};

      function sendSuccess() {
        try {
          if (window.opener && !window.opener.closed) {
            window.opener.postMessage(payload, '*');
            window.close();
            return true;
          }
          if (window.parent && window.parent !== window) {
            window.parent.postMessage(payload, '*');
            return true;
          }
        } catch (e) {}
        return false;
      }

      // If we have an opener, do the Decap handshake first
      if (window.opener && !window.opener.closed) {
        try {
          window.opener.postMessage('authorizing:github', '*');
        } catch (e) {}

        function receiveMessage() {
          // Once we get *any* reply, send the token
          window.removeEventListener('message', receiveMessage, false);
          sendSuccess();
        }

        window.addEventListener('message', receiveMessage, false);

        // Fallback: if no reply comes back, still try after a moment
        setTimeout(function () {
          window.removeEventListener('message', receiveMessage, false);
          sendSuccess();
        }, 800);
      } else {
        // No opener, just try sending anyway (won't work) and show a message.
        var ok = sendSuccess();
        if (!ok) {
          document.body.innerHTML =
            '<p>Authorized, but this window was not opened by Decap CMS. Close it and log in from /admin.</p>';
        }
      }
    })();
  </script>
</body>
</html>`,
    { headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
};
const handleCallback = async (url: URL, env: Env) => {
  const code = url.searchParams.get('code');
  if (!code) return new Response('Missing code', { status: 400 });

  const oauth2 = createOAuth(env);
  const accessToken = await oauth2.getToken({
    code,
    redirect_uri: `https://${url.hostname}/callback`,
  });

  const token =
    typeof accessToken === "string"
      ? accessToken
      : (accessToken as any)?.access_token || (accessToken as any)?.token;

  if (!token) return new Response("No access token returned", { status: 500 });

  return callbackScriptResponse('success', token);
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
    console.log(`url.pathname is ${url.pathname}`);
		if (url.pathname === '/auth') {
			return handleAuth(url, env);
		}
		if (url.pathname === '/callback') {
			return handleCallback(url, env);
		}
		return new Response('Hello 👋');
	},
};
