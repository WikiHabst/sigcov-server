/* eslint-env node, es6 */

const express = require('express');
// bot framework for interacting with the wiki, see https://www.npmjs.com/package/mwn
const {mwn} = require('mwn');
// sql client for database accesses, see https://www.npmjs.com/package/mysql2
const mysql = require('mysql2/promise');
const cors = require('cors');
const jsdom = require('jsdom');
const passport = require('passport');
const session = require('express-session');
const MediaWikiStrategy = require('passport-mediawiki-oauth').OAuthStrategy;
const { Sequelize, DataTypes } = require('sequelize');
const JSDOM = jsdom.JSDOM;

global.DOMParser = new JSDOM().window.DOMParser;

// bot account and database access credentials, if needed
const credentials = require('./credentials.json');
const port = parseInt(process.env.PORT, 10); // necessary for the tool to be discovered by the nginx proxy

async function getDbConnection() {
	return await mysql.createConnection({
		host: 'enwiki.analytics.db.svc.eqiad.wmflabs',
		port: 3306,
		user: credentials.db_user,
		password: credentials.db_password,
		database: 'enwiki_p'
	});
}

(async function() {
  const app = express();
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json()); // for parsing the body of POST requests
  app.use(express.static('static')); // serve files in the static directory
  app.use(cors());
  app.set('trust proxy', 1);
  app.use(session({
    secret: credentials.session_secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 60000000000,
      secure: true, // Toolforge runs HTTPS
      sameSite: 'lax'
    },
  }));
  app.use(passport.initialize());
  app.use(passport.session());
  const client = new mwn({
    apiUrl: 'https://en.wikipedia.org/w/api.php',
    username: credentials.bot_username,
    password: credentials.bot_password
  });
  const sequelize = new Sequelize(credentials.dbname, credentials.dbuser, credentials.dbpass, {
    host: 'tools.db.svc.wikimedia.cloud',
    dialect: 'mariadb',
  });
  async function testConnection() {
    try {
      await sequelize.authenticate();
      console.log('Connection has been established successfully.');
    } catch (error) {
      console.error('Unable to connect to the database:', error);
    }
  }
  await testConnection();
  const User = sequelize.define('User', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    username: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
    },
    score: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
    token: {
      type: DataTypes.STRING,
    }
  });
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findByPk(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
  passport.use(new MediaWikiStrategy({
      consumerKey: credentials.oauth_1_clientid,
      consumerSecret: credentials.oauth_1_secret,
      callbackURL: 'https://sigcovhunter.toolforge.org/callback'
    },
    async function(token, tokenSecret, profile, done) {
      try {
        const [user, created] = await User.findOrCreate({
          where: { username: profile._json.username },
        });
        await user.update({ token: token });
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));
	// need to do either a .getSiteInfo() or .login() before we can use the client object
	await client.getSiteInfo();
  await sequelize.sync();

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

  app.get('/login', passport.authenticate('mediawiki', { scope: 'email' /* ? */ }));
  app.get('/callback', (req, res, next) => {
    console.log('req._passport:', req._passport);
    next();
  }, passport.authenticate('mediawiki', { failureRedirect: '/failure' }), (req, res) => {
    res.redirect('/success');
  });

  const ns = {};
  const ocr = {};
  app.get('/news', async (req, res) => {
    try {
      const { title } = req.query;
      const [base, dab = ''] = title.split(' (');
      const keyword = `"${base}" ${dab.slice(0, -1)}`.trim();
      ns[keyword] ??= await (await fetch(`https://www.newspapers.com/api/search/query?${new URLSearchParams({
        keyword,
        sort: 'paper-date-asc',
        'entity-types': 'page,obituary,marriage,birth,enslavement',
        count: '100',
      })}`)).json();
      const matches = [];
      for (const rec of ns[keyword].records.slice(0, 2)) {
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
          const snip = ocr[pgid].text.slice(i - 200, i + base.length + 200).replaceAll(new RegExp(base, 'ig'), `**${base}**`);
          matches.push({
            snip,
            publication: rec.publication, // id, name, location
            date: rec.page.date,
            pageNo: rec.page.pageNumber,
            url: pgUrl,
          });
        }
      }
      res.send(matches);
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
        await sequelize.sync({ force: true });
      }
      res.sendStatus(200);
    } catch (e) {
      res.status(500).send(e);
    }
  })

	app.post('/post_endpoint', (req, res) => {
		// req.body gives the POST body
		res.send('Hello World!');
	});

	// Sample GET endpoint that returns the wikitext of a specified page
	app.get('/read_wiki_page', (req, res) => {
		var page_name = req.query.page;
		client.read(page_name).then(pg => {
			var page_text = pg.revisions[0].content;
			res.send(page_text);
		});
	});

	app.listen(port, () => console.log(`Example app listening at port ${port}`));

})();
