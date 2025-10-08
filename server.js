/* eslint-env node, es6 */

const express = require('express');
// sql client for database accesses, see https://www.npmjs.com/package/mysql2
const mysql = require('mysql2/promise');
const cors = require('cors');
const jsdom = require('jsdom');
const passport = require('passport');
const session = require('express-session');
const OAuth2Strategy = require('passport-oauth2');
const axios = require('axios');
const JSDOM = jsdom.JSDOM;
const { User, OAuthToken, init } = require('./models');

const MW_WIKI_BASE = "https://en.wikipedia.org";
const AUTHORIZATION_URL = `${MW_WIKI_BASE}/w/rest.php/oauth2/authorize`;
const TOKEN_URL = `${MW_WIKI_BASE}/w/rest.php/oauth2/access_token`;
const PROFILE_URL = `${MW_WIKI_BASE}/w/rest.php/oauth2/resource/profile`;

global.DOMParser = new JSDOM().window.DOMParser;

// bot account and database access credentials, if needed
const credentials = require('./credentials.json');
const port = parseInt(process.env.PORT, 10); // necessary for the tool to be discovered by the nginx proxy

// passport serialize/deserialize
passport.serializeUser((user, done) => {
  done(null, user.sub);
});
passport.deserializeUser(async (sub, done) => {
  try {
    const user = await User.findOne({ where: { sub }, include: ['tokens'] });
    done(null, user || null);
  } catch (err) {
    done(err);
  }
});

// Create a custom OAuth2 strategy that fetches profile from MediaWiki
class MediaWikiOAuth2Strategy extends OAuth2Strategy {
  constructor(options, verify) {
    super(options, verify);
    this.name = 'mediawiki';
  }
  userProfile(accessToken, done) {
    // The MediaWiki profile endpoint requires Authorization: Bearer <token>
    console.log('Fetching user profile with access token...');
    axios.get(PROFILE_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 5000
    })
      .then(res => {
        console.log('Profile response:', res.data);
        // expected response contains fields like sub, username, email, groups, etc
        const profile = res.data;
        // normalize profile to passport-style object
        const normalized = {
          provider: 'mediawiki',
          id: profile.sub || profile.username,
          sub: profile.sub,
          username: profile.username,
          json: profile
        };
        done(null, normalized);
      })
      .catch(err => {
        done(err);
      });
  }
}

passport.use('mediawiki', new MediaWikiOAuth2Strategy({
  authorizationURL: AUTHORIZATION_URL,
  tokenURL: TOKEN_URL,
  clientID: credentials.oauth_2_clientid,
  clientSecret: credentials.oauth_2_secret,
  callbackURL: 'https://sigcovhunter.toolforge.org/callback',
  passReqToCallback: false,
  skipUserProfile: false,
}, async (accessToken, refreshToken, params, profile, done) => {
  // params often contains expires_in, scope, token_type
  try {
    // If passport's userProfile didn't run automatically, attempt to fetch
    if (!profile || !profile.sub) {
      // attempt to GET profile
      const resp = await axios.get(PROFILE_URL, { headers: { Authorization: `Bearer ${accessToken}` } });
      profile = {
        provider: 'mediawiki',
        id: resp.data.sub || resp.data.username,
        sub: resp.data.sub,
        username: resp.data.username,
        json: resp.data
      };
    }

    // upsert user
    let user = await User.findOne({ where: { sub: String(profile.sub || profile.id) } });
    if (user) {
      await user.update({
        username: profile.username || profile.id,
        profile: profile.json || profile
      });
    } else {
      user = await User.create({
        sub: String(profile.sub || profile.id),
        username: profile.username || profile.id,
        profile: profile.json || profile
      });
    }

    // save token associated with user
    const expiresAt = params && params.expires_in ? new Date(Date.now() + (params.expires_in * 1000000000)) : null;
    await OAuthToken.create({
      accessToken,
      refreshToken,
      scope: params && params.scope ? params.scope : null,
      tokenType: params && params.token_type ? params.token_type : null,
      expiresAt,
      UserId: user.id
    });

    // attach profile object for express req.user
    const userWithTokens = await User.findByPk(user.id, { include: ['tokens'] });
    done(null, userWithTokens);
  } catch (err) {
    done(err);
  }
}));

const app = express();
app.use(express.json()); // for parsing the body of POST requests
app.use(express.static('static')); // serve files in the static directory
app.use(cors({
  origin: true,
  credentials: true,
}));
app.set('trust proxy', 1);
app.use(session({
  secret: credentials.session_secret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: 'lax', // change to none
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Serve index.html as the homepage
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/static/index.html');
});

app.get('/me', (req, res) => {
  if (req.user) {
    res.send(req.user);
  } else {
    res.status(404).send({ message: 'User not found' });
  }
});

app.get('/login', (req, res, next) => {
  // you can pass extra options e.g. scope, state, prompt
  const opts = {
    // example scope: 'openid profile email' — your consumer registration determines allowed grants
    scope: req.query.scope || undefined,
    state: req.query.state || undefined
  };
  passport.authenticate('mediawiki', opts)(req, res, next);
});

app.post('/edit', async (req, res, next) => {
  try {
    if (!req.body.title || !req.body.text) {
      return res.status(300).send("Need title and text");
    }
    const oauthToken = credentials.env === 'dev' ? credentials.oauthToken : req.user.tokens.at(-1).accessToken;
    const tokenResp = await (await fetch('https://en.wikipedia.org/w/api.php?' + new URLSearchParams({
      action: 'query',
      meta: 'tokens',
      format: 'json',
    }), {
      headers: { Authorization: `Bearer ${oauthToken}` },
    })).json();
    console.log('tokenResp', tokenResp);
    const csrfToken = tokenResp.query.tokens.csrftoken;
    const r = await (await fetch(`https://en.wikipedia.org/w/api.php?${new URLSearchParams({
      action: 'edit',
      format: 'json',
    })}`, {
      method: 'POST',
      body: new URLSearchParams({
        title: req.body.title,
        section: req.body.section ?? '0',
        summary: req.body.summary ?? 'Adding reference with SIGCOV Hunter',
        text: req.body.text,
        token: csrfToken,
      }),
      headers: { Authorization: `Bearer ${oauthToken}` },
    })).json();
    if (r.edit?.result === 'Success') {
      if (req.user) {
        const user = await User.findByPk(req.user.id);
        if (user) await user.update({ 
          score: user.score + 1,
        });
      } else {
        console.log('edit user not found', r);
      }
    }
    res.send(r);
  } catch (e) {
    console.error(e);
    res.status(500).send(e);
  }
});

app.get('/wiki/:page(*)', (req, res) => {
  const page = req.params.page;
  res.redirect(302, `https://en.wikipedia.org/wiki/${page}`);
});
app.get('/w/:page(*)', (req, res) => {
  const page = req.params.page;
  res.redirect(302, `https://en.wikipedia.org/w/${page}`);
});

app.get('/top', async (req, res, next) => {
  try {
    const topUsers = await User.findAll({
      attributes: ['username', 'score'],
      order: [['score', 'DESC']],
      limit: 10
    });
    res.send(topUsers);
  } catch (e) {
    res.status(500).send(e);
  }
})

app.get('/callback', (req, res, next) => {
  passport.authenticate('mediawiki', (err, user, info) => {
    if (err) {
      console.error('OAuth error:', err);
      return res.redirect(`/failure?err=${encodeURIComponent(err.message || 'OAuth error')}`);
    }
    if (!user) {
      console.warn('No user returned from OAuth:', info);
      return res.redirect(`/failure?info=${encodeURIComponent(JSON.stringify(info || {}))}`);
    }
    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error('Login error:', loginErr);
        return res.redirect(`/failure?err=${encodeURIComponent(loginErr.message || 'Login error')}`);
      }
      // return res.redirect('http://localhost:5173/');
      return res.redirect('/');
    });
  })(req, res, next);
});

app.get('/failure', (req, res) => {
  const err = req.query.err || '';
  const info = req.query.info || '';
  res.status(401).send(`
    <h2>Login failed</h2>
    <pre>${err || info || 'Unknown error'}</pre>
    <p><a href="/login">Try again</a></p>
  `);
});

const ns = {};
const ocr = {};
app.get('/news', async (req, res) => {
  try {
    const { title, pg = 0 } = req.query;
    const PGSIZE = 3;
    const endIdx = pg * PGSIZE + PGSIZE;
    const [base, dab = ''] = title.split(' (');
    const keyword = `"${base}" ${dab.slice(0, -1)}`.trim();
    ns[keyword] ??= await (await fetch(`https://www.newspapers.com/api/search/query?${new URLSearchParams({
      keyword,
      // sort: 'paper-date-asc',
      sort: 'score-desc',
      'entity-types': 'page,obituary,marriage,birth,enslavement',
      count: '10',
    })}`)).json();
    const matches = [];
    for (const rec of ns[keyword].records.slice(pg * PGSIZE, endIdx)) {
      console.log(rec);
      const pgid = rec.page.id;
      const pgUrl = `https://www.newspapers.com/newspage/${pgid}/`;
      if (!ocr[pgid]) {
        const html = await (await fetch(pgUrl, {
          headers: { cookie: credentials.nscookie },
        })).text();
        const doc = new DOMParser().parseFromString(html, 'text/html');
        ocr[pgid] = JSON.parse(doc.querySelector('#mainContent script')?.innerHTML ?? 'null');
      }
      const idxs = [...(ocr[pgid]?.text.matchAll(new RegExp(base, 'ig')) ?? [])].map(m => m.index);
      for (const i of idxs) {
        const baseMatch = ocr[pgid].text.slice(i, i + base.length);
        const snip = ocr[pgid].text.slice(i - 300, i + base.length + 300).replace(new RegExp(base, 'i'), `||||`);
        matches.push({
          snipBefore: snip.split('||||')[0],
          baseMatch,
          snipAfter: snip.split('||||')[1],
          publication: rec.publication, // id, name, location
          date: rec.page.date,
          pageNo: rec.page.pageNumber,
          url: pgUrl,
        });
      }
    }
    res.send({
      hasMore: endIdx < ns[keyword].records.length,
      hits: matches,
    });
  } catch (e) {
    console.log(e)
    res.send(e);
  }
});

app.get('/test-session', (req, res) => {
  console.log(req.session);
  res.send(req.session);
});

app.get('/sync', async (req, res) => {
  try {
    if (req.query.password === credentials.session_secret) {
      await init({ force: true });
    }
    res.sendStatus(200);
  } catch (e) {
    res.status(500).send(e);
  }
});

(async () => {
  try {
    await init();
    app.listen(port, () => console.log(`Example app listening at port ${port}`));
  } catch (err) {
    console.error('Failed to initialize DB or start server', err);
    process.exit(1);
  }
})();
