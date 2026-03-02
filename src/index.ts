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
      var payload = 'authorization:github:${status}:' + JSON.stringify({ token: ${JSON.stringify(token)} });

      if (window.opener && !window.opener.closed) {
        window.opener.postMessage(payload, '*');
        window.close();
        return;
      }

      if (window.parent && window.parent !== window) {
        window.parent.postMessage(payload, '*');
        return;
      }

      document.body.innerHTML = '<p>Login successful. You may close this tab.</p>';
    })();
  </script>
</body>
</html>`,
		{
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		}
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
