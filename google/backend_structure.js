require('dotenv').config();

const express = require('express');   // creare API REST
const cors = require('cors');   // gestisce le richieste cross-origin
const mysql = require('mysql2/promise');    // driver MySQL
const AWS = require('aws-sdk');   // integra servizi AWS
const jwt = require('jsonwebtoken');    // crea e verifica token JWT per autenticazione
const jwkToPem = require('jwk-to-pem');   // convertire le chiavi JWK (che Cognito fornisce) nel formato PEM necessario per la verifica
const axios = require('axios');   // scaricare le chiavi pubbliche di Cognito

const app = express();    // crea app Express
const port = process.env.PORT || 8080;    // imposta la porta

let pems;   // cache per chiavi pubbliche di Cognito

// Middleware
app.use(cors());    // abilita CORS per tutte le route
app.use(express.json());    // abilita parsing automatico del JSON nelle richieste

// Configurazione AWS
const cognito = new AWS.CognitoIdentityServiceProvider({
  region: process.env.AWS_REGION    // configurato con regione AWS delle variabili d'ambiente
});
const crypto = require('crypto');
const { time } = require('console');

const s3 = new AWS.S3({
  region: process.env.AWS_REGION,    // configurato con regione AWS delle variabili d'ambiente
  signatureVersion: 's3v4'
});

console.log('Nome bucket:', process.env.S3_BUCKET_NAME);
console.log('Regione bucket:', process.env.AWS_REGION);

// Configurazione Database (MySQL)
const dbConfig = {
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  port: 3306,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000
};

const pool = mysql.createPool(dbConfig); // crea pool di connessioni MySQL per gestire le richieste multiple

// Middleware per autenticazione
// verifica se la richiesta contiene un token JWT nell'header "Authorization"
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token non fornito.' });
    }

    try {
        try {
            const localToken = jwt.verify(token, process.env.JWT_SECRET);
            console.log('Token locale verificato per:', localToken.email || localToken.userId);
            
            req.user = {
                sub: localToken.cognitoSub || localToken.email,
                email: localToken.email,
                userId: localToken.userId,
                nome: localToken.nome
            };
            
            return next();
        } catch (localError) {
            console.log('Non è un token locale, provo con Cognito...');
        }
        
        const decodedJwt = jwt.decode(token, { complete: true });
        if (!decodedJwt) {
            return res.status(401).json({ error: 'Token non valido.' });
        }

        const kid = decodedJwt.header.kid;
        if (!kid) {
            return res.status(401).json({ error: 'Token senza KID - probabilmente non è un token Cognito valido.' });
        }

        const currentPems = await getCognitoPems();
        const pem = currentPems[kid];
        
        if (!pem) {
            return res.status(401).json({ error: 'Chiave di verifica del token non trovata.' });
        }

        const verifiedToken = jwt.verify(token, pem, { algorithms: ['RS256'] });
        req.user = verifiedToken;
        next();
        
    } catch (error) {
        console.error('Errore nella verifica del token:', error);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token scaduto. Effettua nuovamente il login.' });
        }
        return res.status(401).json({ error: 'Token non valido o scaduto.' });
    }
}

// scarica chiavi pubbliche di Cognito
async function getCognitoPems() {
    if (pems) return pems; // Usa la cache se già caricate

    const jwksUrl = `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`;
    try {
        const response = await axios.get(jwksUrl);
        const jwks = response.data.keys;
        pems = {};
        for (let i = 0; i < jwks.length; i++) {
            const jwk = jwks[i];
            const pem = jwkToPem({ kty: jwk.kty, n: jwk.n, e: jwk.e });
            pems[jwk.kid] = pem;
        }
        return pems;
    } catch (error) {
        console.error('Errore nel recupero delle chiavi JWKS di Cognito:', error);
        throw new Error('Impossibile recuperare le chiavi pubbliche Cognito.');
    }
}

// ============== AUTHENTICATION ROUTES ==============

// Login utente con Cognito
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email e password richiesti' });
    }

    const [userRows] = await pool.execute(
      'SELECT id, nome, email, cognito_sub FROM utenti WHERE email = ?',
      [email]
    );

    if (userRows.length === 0) {
      return res.status(401).json({ 
        error: 'Email o password non corretti. Controlla le tue credenziali e riprova.' 
      });
    }

    const user = userRows[0];

    const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
    const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;

    const hmac = crypto.createHmac('sha256', CLIENT_SECRET);
    hmac.update(email + CLIENT_ID);
    const secretHash = hmac.digest('base64');

    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      //UserPoolId: process.env.COGNITO_USER_POOL_ID,
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
        SECRET_HASH: secretHash
      }
    };
    
    let result;
    try {
      result = await cognito.initiateAuth(params).promise();
    } catch (cognitoError) {
      console.error('Errore Cognito durante login:', cognitoError);

      if (cognitoError.code === 'UserNotConfirmedException') {
        console.log('Utente non confermato, tento conferma automatica:', email);
        
        try {
          await cognito.adminConfirmSignUp({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Username: email
          }).promise();
          
          console.log('Utente confermato automaticamente:', email);
          
          result = await cognito.initiateAuth(params).promise();
          
        } catch (confirmError) {
          console.error('Errore nella conferma automatica:', confirmError);
          
          console.log('Fallback: usando autenticazione locale per:', email);
          
          const token = jwt.sign(
            { 
              sub: user.cognito_sub || user.email,
              email: email,
              cognitoSub: user.cognito_sub,
              userId: user.id,
              nome: user.nome
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
          );
          
          return res.json({
            message: 'Login effettuato con successo (modalità locale)',
            accessToken: token,
            refreshToken: null,
            idToken: token,
            appToken: token,
            user: {
              id: user.id,
              nome: user.nome,
              email: user.email
            }
          });
        }
      }
      
      if (cognitoError.code === 'NotAuthorizedException') {
        return res.status(401).json({ 
          error: 'Email o password non corretti. Controlla le tue credenziali e riprova.' 
        });
      } else if (cognitoError.code === 'UserNotFoundException') {
        return res.status(401).json({ 
          error: 'Account non trovato. Verifica l\'email o registrati se non hai ancora un account.' 
        });
      } else if (cognitoError.code === 'PasswordResetRequiredException') {
        return res.status(401).json({ 
          error: 'È necessario reimpostare la password. Contatta l\'amministratore del sistema.' 
        });
      } else if (cognitoError.code === 'TooManyRequestsException') {
        return res.status(429).json({ 
          error: 'Troppi tentativi di login. Attendi qualche minuto prima di riprovare.' 
        });
      } else if (cognitoError.code === 'InvalidParameterException') {
        return res.status(400).json({ 
          error: 'Parametri di login non validi. Controlla email e password.' 
        });
      } else {
        return res.status(500).json({ 
          error: 'Errore del servizio di autenticazione: ' + (cognitoError.message || 'Errore sconosciuto') 
        });
      }
    }
    
    console.log('Login Cognito riuscito per:', email);
    
    const token = jwt.sign(
      { 
        sub: user.cognito_sub || user.email,
        email: email,
        //cognitoSub: result.AuthenticationResult.AccessToken,
        cognitoSub: user.cognito_sub, 
        userId: user.id,
        nome: user.nome
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    return res.json({
      message: 'Login effettuato con successo',
      /*accessToken: result.AuthenticationResult.AccessToken,
      refreshToken: result.AuthenticationResult.RefreshToken,
      idToken: result.AuthenticationResult.IdToken,*/
      accessToken: token,
      refreshToken: token,  // Usa lo stesso token
      idToken: token,
      appToken: token,
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email
      }
    });
    
  } catch (error) {
    console.error('Errore generico login:', error);
    res.status(500).json({ 
      error: 'Errore interno del server durante il login. Riprova più tardi.' 
    });
  }
});

// Registrazione per AWS Academy
app.post('/api/auth/register', async (req, res) => {
  const connection = await pool.getConnection();
  await connection.beginTransaction();
  
  try {
    const { name, email, password, genres, mood } = req.body;
    
    if (!name || !email || !password || !genres || !Array.isArray(genres) || genres.length === 0 || !mood) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ error: 'Dati mancanti o non validi' });
    }
    
    // Validazione password
    const passwordErrors = validatePasswordServer(password);
    if (passwordErrors.length > 0) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ 
        error: 'Password non valida:\n' + passwordErrors.join('\n')
      });
    }
    
    // Verifica se email già esiste
    const [existingUser] = await connection.execute(
      'SELECT email FROM utenti WHERE email = ?',
      [email]
    );

    if (existingUser.length === 0) {
      try {
        await cognito.adminGetUser({
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
          Username: email
        }).promise();
        
        console.log('Utente trovato in Cognito ma non nel DB, elimino da Cognito:', email);
        
        await cognito.adminDeleteUser({
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
          Username: email
        }).promise();
        
        console.log('Utente eliminato da Cognito, procedo con registrazione');
        
      } catch (cognitoGetError) {
        console.log('Utente non esiste in Cognito, procedo normalmente');
      }
    }
    
    if (existingUser.length > 0) {
      await connection.rollback();
      connection.release();
      return res.status(409).json({ error: 'Email già registrata nel sistema' });
    }
    
    const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
    const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;

    const hmac = crypto.createHmac('sha256', CLIENT_SECRET);
    hmac.update(email + CLIENT_ID);
    const secretHash = hmac.digest('base64');

    const cognitoParams = {
      ClientId: CLIENT_ID,
      Username: email,
      Password: password,
      SecretHash: secretHash,
      UserAttributes: [
        { Name: 'email', Value: email },
        { Name: 'name', Value: name }
      ]
    };
    
    let cognitoResult;
    try {
      cognitoResult = await cognito.signUp(cognitoParams).promise();
      console.log('SignUp result:', cognitoResult);
      
      if (cognitoResult.UserSub) {
        try {
          await cognito.adminConfirmSignUp({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Username: email
          }).promise();
          console.log('Utente confermato automaticamente:', email);
        } catch (confirmError) {
          console.error('Errore nella conferma automatica:', confirmError);
          try {
            await cognito.adminSetUserPassword({
              UserPoolId: process.env.COGNITO_USER_POOL_ID,
              Username: email,
              Password: password,
              Permanent: true
            }).promise();
            console.log('Password impostata come permanente per:', email);
          } catch (passwordError) {
            console.error('Errore impostazione password permanente:', passwordError);
          }
        }
      }
      
    } catch (cognitoError) {
      await connection.rollback();
      connection.release();
      
      console.error('Errore Cognito durante registrazione:', cognitoError);
      
      if (cognitoError.code === 'UsernameExistsException') {
        return res.status(409).json({ error: 'Email già registrata in Cognito' });
      } else if (cognitoError.code === 'InvalidPasswordException') {
        return res.status(400).json({ 
          error: 'Password non valida: deve contenere almeno 8 caratteri, una maiuscola, una minuscola, un numero e un carattere speciale' 
        });
      } else {
        return res.status(500).json({ 
          error: 'Errore durante la registrazione: ' + cognitoError.message 
        });
      }
    }

    // Salva nel database
    const genresToSave = JSON.stringify(genres);
    const cognitoSub = cognitoResult.UserSub;
    
    const query = `
      INSERT INTO utenti (nome, email, generi_preferiti, mood_attuale, cognito_sub, data_creazione, data_aggiornamento)
      VALUES (?, ?, ?, ?, ?, NOW(), NOW())
    `;
    
    const [result] = await connection.execute(query, [name, email, genresToSave, mood, cognitoSub]);
    
    await connection.commit();
    connection.release();
    
    res.status(201).json({
      message: 'Utente registrato con successo. Puoi ora effettuare il login.',
      user: {
        id: result.insertId,
        nome: name,
        email: email
      }
    });
    
  } catch (error) {
    await connection.rollback();
    connection.release();
    
    console.error('Errore registrazione:', error);
    res.status(500).json({ error: 'Errore interno del server durante la registrazione' });
  }
});

// Logout utente
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.body;
    
    if (accessToken) {
      await cognito.globalSignOut({
        AccessToken: accessToken
      }).promise();
    }
    
    res.json({ message: 'Logout effettuato con successo' });
    
  } catch (error) {
    console.error('Errore logout:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// ============== USER ROUTES ==============

app.post('/api/songs/presigned-upload', authenticateToken, async (req, res) => {
  try{
    const { fileName, fileType } = req.body;

    if (!fileName || !fileType){
      return res.status(400).json({error: 'Nome file e tipo richiesti'});
    }
    let folder = 'canzoni';
    if (fileType.startsWith('image/')) {
      folder = 'copertine';
    }

    const timestamp = Date.now();
    const userSub = req.user.sub || 'unknown';
    const sanitizedFileName = fileName.replace(/[^a-zA-Z0-9.-]/g, '_');
    const key = `${folder}/${timestamp}-${userSub}-${sanitizedFileName}`;

    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
      ContentType: fileType,
      Expires: 300,
      Metadata: {
        'uploaded-by': userSub,
        'upload-timestamp': timestamp.toString()
      }
    };

    const signedUrl = s3.getSignedUrl('putObject', params);
    console.log(`Pre-signed upload URL generato per: ${key}`)

    res.json({
      uploadUrl: signedUrl,
      key: key,
      bucket: process.env.S3_BUCKET_NAME,
      expires: new Date(Date.now() + 300000).toISOString(),
      contentType: fileType
    });
  } catch (error){
    console.error('Errore generazione presigned URL', error);
    res.status(500).json({ error: 'Errore interno del server'});
  }
});

app.get('/api/songs/:songId/stream-url', authenticateToken, async (req, res) => {
  try{
    const { songId } = req.params;

    const [songRows] = await pool.execute(
      'SELECT id, titolo, artista, url_s3 FROM canzoni WHERE id = ?',
      [songId]
    );

    if(songRows.length === 0){
      return res.status(404).json({ error: 'Canzone non trovata'});
    }

    const song = songRows[0];

    let s3Key;
    if(song.url_s3.includes('.amazonaws.com/')){
      s3Key = song.url_s3.split('.amazonaws.com/')[1];
    } else {
      s3Key = song.url_s3;
    }

    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: s3Key,
      Expires: 3600,
      ResponseContentDisposition: `inline; filename="${song.titolo} - ${song.artista}.mp3"`,
      ResponseContentType: 'audio/mpeg'
    };

    const streamUrl = s3.getSignedUrl('getObject', params);

    console.log(`Pre-signed stream URL generato per canzone: ${song.titolo}`);

    res.json({
      streamUrl: streamUrl,
      songId: song.id,
      songTitle: song.titolo,
      artist: song.artista,
      expires: new Date(Date.now() + 3600000).toISOString()
    });
  } catch (error){
    console.error('Errore nella generazione pre-signed URL per streaming:', error);
    res.status(500).json({ error: 'Errore interno del server durante generazione pre-signed URL stream'});
  }
})

app.get('/api/songs/:songId/cover-url', authenticateToken, async (req, res) => {
  try {
    const { songId } = req.params;
    
    const [songRows] = await pool.execute(
      'SELECT id, titolo, url_immagine_copertina FROM canzoni WHERE id = ?',
      [songId]
    );
    
    if (songRows.length === 0 || !songRows[0].url_immagine_copertina) {
      return res.status(404).json({ error: 'Copertina non trovata per questa canzone' });
    }
    
    const song = songRows[0];
    
    let s3Key;
    if (song.url_immagine_copertina.includes('.amazonaws.com/')) {
      s3Key = song.url_immagine_copertina.split('.amazonaws.com/')[1];
    } else {
      s3Key = song.url_immagine_copertina;
    }
    
    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: s3Key,
      Expires: 3600, // 1 ora
      ResponseContentDisposition: `inline; filename="${song.titolo}-cover.jpg"`
    };
    
    const coverUrl = s3.getSignedUrl('getObject', params);
    
    console.log(`Pre-signed cover URL generato per canzone: ${song.titolo}`);
    
    res.json({
      coverUrl: coverUrl,
      songId: song.id,
      songTitle: song.titolo,
      expires: new Date(Date.now() + 3600000).toISOString()
    });
    
  } catch (error) {
    console.error('Errore generazione pre-signed URL per copertina:', error);
    res.status(500).json({ error: 'Errore interno del server durante generazione URL copertina' });
  }
});

// Health check
// verifica che il server sia attivo
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Ready check
// verifica che il DB sia raggiungibile
app.get('/ready', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute('SELECT 1');
    connection.release();
    res.status(200).json({ status: 'READY' });
  } catch (error) {
    res.status(503).json({ status: 'NOT_READY', error: error.message });
  }
});

app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const cognitoSub = req.user.sub; // Questo è l'ID univoco dell'utente Cognito

        console.log('Cognito Sub estratto dal token:', cognitoSub);

        // Recupera i dati dell'utente dal tuo DB locale usando il cognitoSub
        const [rows] = await pool.execute(
            'SELECT id, nome, email, generi_preferiti, mood_attuale FROM utenti WHERE cognito_sub = ?',
            [cognitoSub]
        );

        console.log('Risultato query DB (rows):', rows);

        if (rows.length > 0) {
            const user = rows[0];
            let parsedGenres = [];
            if (user.generi_preferiti !== null && user.generi_preferiti !== undefined) {
                try {
                    if (Array.isArray(user.generi_preferiti)) {
                        parsedGenres = user.generi_preferiti;
                    } 
                    else if (typeof user.generi_preferiti === 'string') {
                        if (user.generi_preferiti.startsWith('[') && user.generi_preferiti.endsWith(']')) {
                            parsedGenres = JSON.parse(user.generi_preferiti);
                        } else {
                            parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
                        }
                    }
                } catch (e) {
                    console.error("Errore nel parsing dei generi durante il recupero del profilo:", e);
                    console.error("Valore generi_preferiti:", user.generi_preferiti, "Tipo:", typeof user.generi_preferiti);
                    
                    if (typeof user.generi_preferiti === 'string') {
                        parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
                    } else {
                        parsedGenres = [];
                    }
                }
            }
            res.status(200).json({
                id: user.id,
                nome: user.nome,
                email: user.email,
                generi_preferiti: parsedGenres,
                mood_attuale: user.mood_attuale
            });
        } else {
            res.status(404).json({ error: 'Profilo utente non trovato nel DB locale.' });
        }
    } catch (error) {
        console.error('Errore nel recupero del profilo utente:', error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

// Ottenere profilo utente
// richiede autenticazione, estrae ID utente dall'URL e restituisce i dati del profilo utente
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const query = `
      SELECT id, nome, email, generi_preferiti, mood_attuale, data_creazione, data_aggiornamento
      FROM utenti WHERE id = ?
    `;
    
    const [rows] = await pool.execute(query, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    const user = rows[0];
    
    // Gestione sicura del parsing dei generi
    let parsedGenres = [];
    if (user.generi_preferiti !== null && user.generi_preferiti !== undefined) {
      try {
        // Verifica se è già un array
        if (Array.isArray(user.generi_preferiti)) {
          parsedGenres = user.generi_preferiti;
        } else if (typeof user.generi_preferiti === 'string') {
          // Prova a fare il parsing JSON
          if (user.generi_preferiti.startsWith('[') && user.generi_preferiti.endsWith(']')) {
            parsedGenres = JSON.parse(user.generi_preferiti);
          } else {
            // Se è una stringa separata da virgole, dividila
            parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
          }
        }
      } catch (e) {
        console.error("Errore nel parsing dei generi:", e);
        console.error("Valore generi_preferiti:", user.generi_preferiti);
        // Fallback: prova a dividere per virgole
        if (typeof user.generi_preferiti === 'string') {
          parsedGenres = user.generi_preferiti.split(',').map(g => g.trim());
        } else {
          parsedGenres = [];
        }
      }
    }
    
    // Restituisci l'utente con i generi parsati correttamente
    const userResponse = {
      id: user.id,
      nome: user.nome,
      email: user.email,
      generi_preferiti: parsedGenres,
      mood_attuale: user.mood_attuale,
      data_creazione: user.data_creazione,
      data_aggiornamento: user.data_aggiornamento
    };
    
    res.json(userResponse);
    
  } catch (error) {
    console.error('Errore recupero utente:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

/*
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken, email } = req.body; 

        if (!refreshToken || !email) {
            return res.status(400).json({ error: 'Refresh token ed email sono richiesti.' });
        }

        const [userRows] = await pool.execute(
            'SELECT cognito_sub FROM utenti WHERE email = ?',
            [email]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ error: 'Utente non trovato.' });
        }

        const cognitoUsername = userRows[0].cognito_sub;

        const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
        const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;

        const hmac = crypto.createHmac('sha256', CLIENT_SECRET);
        hmac.update(cognitoUsername + CLIENT_ID);
        const secretHash = hmac.digest('base64');

        console.log('Calculated SECRET_HASH:', secretHash);

        const cognitoParams = {
            AuthFlow: 'REFRESH_TOKEN_AUTH', 
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            ClientId: CLIENT_ID,
            AuthParameters: {
                REFRESH_TOKEN: refreshToken,
                USERNAME: cognitoUsername,
                SECRET_HASH: secretHash
            }
        };

        const result = await cognito.adminInitiateAuth(cognitoParams).promise();

        res.status(200).json({
            message: 'Token rinfrescati con successo!',
            AuthenticationResult: result.AuthenticationResult,
            idToken: result.AuthenticationResult.IdToken,
            refreshToken: result.AuthenticationResult.RefreshToken || refreshToken
        });

    } catch (error) {
        console.error('Errore durante il refresh del token:', error);
        if (error.code === 'NotAuthorizedException' || error.code === 'InvalidGrantException') {
            res.status(401).json({ error: 'Refresh token non valido o scaduto. Si prega di effettuare nuovamente il login.' });
        } else {
            res.status(500).json({ error: 'Errore interno del server durante il refresh del token.' });
        }
    }
});*/

app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken, email } = req.body; 

        if (!refreshToken || !email) {
            return res.status(400).json({ error: 'Refresh token ed email sono richiesti.' });
        }

        const [userRows] = await pool.execute(
            'SELECT id, nome, email, cognito_sub FROM utenti WHERE email = ?',
            [email]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ error: 'Utente non trovato.' });
        }

        const user = userRows[0];
        
        console.log('Generando nuovo token locale per:', email);
        
        const newToken = jwt.sign(
            { 
                email: user.email,
                cognitoSub: user.cognito_sub,
                userId: user.id,
                nome: user.nome
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(200).json({
            message: 'Token rinfrescato con successo (modalità locale)!',
            AuthenticationResult: {
                AccessToken: newToken,
                IdToken: newToken,
                RefreshToken: refreshToken 
            },
            accessToken: newToken,
            idToken: newToken,
            refreshToken: refreshToken
        });

    } catch (error) {
        console.error('Errore durante il refresh del token:', error);
        res.status(500).json({ error: 'Errore interno del server durante il refresh del token.' });
    }
});

// Aggiornare mood utente
// aggiorna il campo "current_mood"
app.put('/api/users/:id/mood', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { mood } = req.body;
    
    if (!mood) {
      return res.status(400).json({ error: 'Mood richiesto' });
    }
    
    const query = `
      UPDATE utenti SET mood_attuale = ?, data_creazione = NOW()
      WHERE id = ?
    `;
    
    const [result] = await pool.execute(query, [mood, id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    // Recuperare l'utente aggiornato
    const [userRows] = await pool.execute(
      'SELECT id, mood_attuale FROM utenti WHERE id = ?',
      [id]
    );
    
    res.json({
      message: 'Mood aggiornato con successo',
      user: userRows[0]
    });
    
  } catch (error) {
    console.error('Errore aggiornamento mood:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere tutte le canzoni (con filtri opzionali)
// endpoint per browsing del catalogo
app.get('/api/songs', authenticateToken, async (req, res) => {
  try {
    const { genre, mood, search } = req.query;

    const limit = Math.max(1, parseInt(req.query.limit) || 20);
    const offset = Math.max(0, parseInt(req.query.offset) || 0);

    if (isNaN(limit) || isNaN(offset)) {
      return res.status(400).json({ 
        error: 'Limit e offset devono essere numeri validi',
        received: { limit: req.query.limit, offset: req.query.offset }
      });
    }
    
    let query = `
      SELECT s.id, s.titolo, s.artista, s.genere, s.tag_mood, s.url_s3, s.durata, s.url_immagine_copertina, s.popolarita, s.data_creazione
      FROM canzoni s
      WHERE 1=1
    `;
    
    const queryParams = [];
    
    // Filtro per genere
    if (genre) {
      query += ` AND s.genere = ?`;
      queryParams.push(genre);
    }
    
    // Filtro per mood
    if (mood) {
      query += ` AND s.tag_mood = ?`;
      queryParams.push(mood);
    }
    
    // Ricerca per titolo o artista
    if (search) {
      query += ` AND (s.titolo LIKE ? OR s.artista LIKE ?)`;
      queryParams.push(`%${search}%`, `%${search}%`);
    }
    
    query += ` ORDER BY s.popolarita DESC, s.data_creazione DESC LIMIT ${limit} OFFSET ${offset}`;

    console.log('Query finale:', query);
    console.log('Parametri:', queryParams);
    
    
    const [songs] = await pool.execute(query, queryParams);
    
    let countQuery = `SELECT COUNT(*) as total FROM canzoni s WHERE 1=1`;
    const countParams = [];
    
    if (genre) {
      countQuery += ` AND s.genere = ?`;
      countParams.push(genre);
    }
    if (mood) {
      countQuery += ` AND s.tag_mood = ?`;
      countParams.push(mood);
    }
    if (search) {
      countQuery += ` AND (s.titolo LIKE ? OR s.artista LIKE ?)`;
      countParams.push(`%${search}%`, `%${search}%`);
    }
    
    const [countRows] = await pool.execute(countQuery, countParams);

    const songsWithParsedMood = songs.map(song => {
      try {
        if (song.tag_mood && typeof song.tag_mood === 'string' && 
            (song.tag_mood.startsWith('[') || song.tag_mood.startsWith('{'))) {
          song.tag_mood = JSON.parse(song.tag_mood);
        }
      } catch (e) {
      }
      return song;
    });
    
    res.json({
      songs: songsWithParsedMood,
      pagination: {
        total: countRows[0].total || 0,
        limit: limit,
        offset: offset,
        hasMore: (offset + limit) < (countRows[0].total || 0)
      }
    });
    
  } catch (error) {
    console.error('Errore recupero canzoni:', error);
    console.error('SQL:', error.sql);
    console.error('Parametri:', error.sqlMessage);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere URL presegnato per upload su S3
// genera URL presegnato per upload diretto su S3
app.post('/api/songs/upload-url', authenticateToken, async (req, res) => {
  try {
    const { fileName, fileType } = req.body;
    
    if (!fileName || !fileType) {
      return res.status(400).json({ error: 'Nome file e tipo file richiesti' });
    }

    let folder = 'canzoni'; 
    if (fileType.startsWith('image/')) {
      folder = 'copertine';
    }
    
    const key = `${folder}/${Date.now()}-${fileName}`;
    
    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
      ContentType: fileType,
      Expires: 3600 // 1 ora
    };
    
    const signedUrl = s3.getSignedUrl('putObject', params);
    
    res.json({
      uploadUrl: signedUrl,
      key: key
    });
    
  } catch (error) {
    console.error('Errore generazione URL:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Salvare informazioni canzone dopo upload
// salva metadati della canzone nel DB
app.post('/api/addSongs', authenticateToken, async (req, res) => {
  try {
    const { title, artist, genre, moodTags, s3Key, duration, coverS3Key } = req.body;
    
    if (!title || !artist || !genre || !s3Key) {
      return res.status(400).json({ error: 'Dati obbligatori mancanti' });
    }

    const s3Url = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3Key}`;
    const coverUrl = coverS3Key ? 
      `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${coverS3Key}` : 
      null;

    const query = `
      INSERT INTO canzoni (titolo, artista, genere, tag_mood, url_s3, durata, url_immagine_copertina, popolarita, data_creazione)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;
      
    const [result] = await pool.execute(query, [
      title,
      artist,
      genre,
      moodTags,
      s3Url,
      duration || 0,
      coverUrl,
      0 // popularity iniziale
    ]);
    
    // Recuperare la canzone appena creata
    const [songRows] = await pool.execute(
      'SELECT id, titolo, artista, genere, tag_mood FROM canzoni WHERE id = ?',
      [result.insertId]
    );
    
    const song = songRows[0];
    song.mood_tags = song.mood_tags;
    
    res.status(201).json({
      message: 'Canzone salvata con successo',
      song: song
    });
    
  } catch (error) {
    console.error('Errore salvataggio canzone:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Valutare una canzone
// permette di valutare una canzone (1-5 stelle)
app.post('/api/songs/:songId/rate', authenticateToken, async (req, res) => {
  try {
    const { songId } = req.params;
    const { rating } = req.body;

    const cognitoSub = req.user.sub;
    
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating deve essere tra 1 e 5' });
    }

    const [userRows] = await pool.execute(
      'SELECT id FROM utenti WHERE cognito_sub = ?',
      [cognitoSub]
    );
    
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }

    const userId = userRows[0].id;
    
    const [songCheck] = await pool.execute(
      'SELECT id, titolo FROM canzoni WHERE id = ?',
      [songId]
    );
    
    if (songCheck.length === 0) {
      return res.status(404).json({ error: 'Canzone non trovata' });
    }

    const songTitle = songCheck[0].titolo;
    
    const query = `
      INSERT INTO feedback_utente (id_utente, id_canzone, nome_canzone, voto_feedback, data_creazione, data_aggiornamento)
      VALUES (?, ?, ?, ?, NOW(), NOW())
      ON DUPLICATE KEY UPDATE
      voto_feedback = VALUES(voto_feedback), nome_canzone = VALUES(nome_canzone), data_aggiornamento = NOW()
    `;
    
    await pool.execute(query, [userId, songId, songTitle, rating]);
    
    const [ratingRows] = await pool.execute(
      'SELECT voto_feedback, nome_canzone, data_creazione, data_aggiornamento FROM feedback_utente WHERE id_utente = ? AND id_canzone = ?',
      [userId, songId]
    );
    
    // Aggiornare la popolarità della canzone basata sui rating
    const updatePopularityQuery = `
            UPDATE canzoni 
            SET popolarita = (
                SELECT ROUND(
                    CASE 
                        WHEN COUNT(*) = 0 THEN 0
                        ELSE AVG(voto_feedback) * LOG(COUNT(*) + 1)
                    END, 1
                )
                FROM feedback_utente 
                WHERE id_canzone = ?
            ) 
            WHERE id = ?
        `;
    
    await pool.execute(updatePopularityQuery, [songId, songId]);
    
    const [popularityRows] = await pool.execute(
        'SELECT popolarita FROM canzoni WHERE id = ?',
        [songId]
    );
        
    res.json({
        message: 'Valutazione salvata con successo',
        rating: ratingRows[0],
        newPopularity: popularityRows[0].popolarita
    });
    
  } catch (error) {
    console.error('Errore valutazione:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere valutazioni utente
// recupera tutte le valutazioni di un utente
app.get('/api/users/:userId/ratings', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 20;
    const offset = parseInt(req.query.offset) || 0;
    
    const query = `
      SELECT 
        fu.id_canzone,
        fu.voto_feedback, 
        fu.nome_canzone,
        fu.data_creazione,
        fu.data_aggiornamento,
        c.artista,
        c.genere,
        c.url_immagine_copertina,
        c.url_s3
      FROM feedback_utente fu
      JOIN canzoni c ON fu.id_canzone = c.id
      WHERE fu.id_utente = ?
      ORDER BY fu.data_aggiornamento DESC
      LIMIT ${limit} OFFSET ${offset}
    `;
    
    const [ratings] = await pool.execute(query, [userId]);

    const countQuery = `
      SELECT COUNT(*) as total 
      FROM feedback_utente 
      WHERE id_utente = ?
    `;
    
    const [countResult] = await pool.execute(countQuery, [userId]);
    const total = countResult[0].total;
    
    res.json({
      ratings: ratings,
      pagination: {
        total: total,
        limit: limit,
        offset: offset,
        hasMore: (offset + limit) < total
      }
    });
    
  } catch (error) {
    console.error('Errore recupero valutazioni:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottenere statistiche generali della piattaforma
// endpoint per dashboard admin
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const statsQuery = `
      SELECT 
        (SELECT COUNT(*) FROM utenti) as total_users,
        (SELECT COUNT(*) FROM canzoni) as total_songs,
        (SELECT COUNT(*) FROM feedback_utente) as total_ratings,
        (SELECT AVG(voto_feedback) FROM feedback_utente) as avg_rating,
        (SELECT COUNT(DISTINCT id_utente) FROM feedback_utente) as active_users
    `;
    
    const [stats] = await pool.execute(statsQuery);
    
    // Top generi
    const genreQuery = `
      SELECT genere, COUNT(*) as count
      FROM canzoni
      GROUP BY genere
      ORDER BY count DESC
      LIMIT 10
    `;
    
    const [genres] = await pool.execute(genreQuery);
    
    res.json({
      stats: stats[0],
      topGenres: genres
    });
    
  } catch (error) {
    console.error('Errore statistiche:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

/* STORICO ROUTE  */

async function saveToHistory(userId, songs, userMood) {
    try {
        for (const song of songs) {
            const checkQuery = `
                SELECT id FROM storico_canzoni 
                WHERE id_utente = ? AND id_canzone = ? AND DATE(data_raccomandazione) = CURDATE()
            `;
            
            const [existing] = await pool.execute(checkQuery, [userId, song.id]);
            
            if (existing.length === 0) {
                const insertQuery = `
                    INSERT INTO storico_canzoni 
                    (id_utente, id_canzone, nome_canzone, artista, genere, mood_utente_al_momento, data_raccomandazione)
                    VALUES (?, ?, ?, ?, ?, ?, NOW())
                `;
                
                await pool.execute(insertQuery, [
                    userId,
                    song.id,
                    song.titolo,
                    song.artista,
                    song.genere,
                    userMood
                ]);
            }
        }
        console.log(`Processate ${songs.length} canzoni per lo storico utente ${userId}`);
    } catch (error) {
        console.error('Errore nel salvataggio storico:', error);
    }
}

app.get('/api/recommendations/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    
    const userQuery = `SELECT generi_preferiti, mood_attuale FROM utenti WHERE id = ?`;
    const [userRows] = await pool.execute(userQuery, [userId]);
    
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    const user = userRows[0];
    let genres = [];
    const mood = user.mood_attuale;

    if (user.generi_preferiti !== null && user.generi_preferiti !== undefined) {
        if (Array.isArray(user.generi_preferiti)) {
            genres = user.generi_preferiti;
        } else if (typeof user.generi_preferiti === 'string') {
            if (user.generi_preferiti.startsWith('[') && user.generi_preferiti.endsWith(']')) {
                genres = JSON.parse(user.generi_preferiti);
            } else {
                genres = user.generi_preferiti.split(',').map(g => g.trim());
            }
        }
    }

    if (genres.length === 0) {
      return res.status(400).json({ error: 'Nessun genere preferito valido trovato per l\'utente.' });
    }
    
    console.log('DEBUG: Generi trovati per utente', userId, ':', genres);
    console.log('DEBUG: Mood utente:', mood);
        
    let allRecommendations = [];
    
    for (const genre of genres) {
      const genreQuery = `
        SELECT s.id, s.titolo, s.artista, s.genere, s.tag_mood, s.url_s3, s.durata, s.url_immagine_copertina, s.popolarita, s.data_creazione
        FROM canzoni s
        WHERE s.genere = ?
        ORDER BY s.popolarita DESC
      `;
      
      console.log(`DEBUG: Query per genere ${genre}:`, genreQuery);
      console.log(`DEBUG: Parametri:`, [genre, mood]);
      
      const [genreResults] = await pool.execute(genreQuery, [genre]);
      allRecommendations = allRecommendations.concat(genreResults);
      
      console.log(`DEBUG: Trovate ${genreResults.length} canzoni per genere ${genre}`);
    }
    
    const uniqueRecommendations = allRecommendations.filter((song, index, self) => 
      index === self.findIndex(s => s.id === song.id)
    );
    
    const finalRecommendations = [];
    for (const song of uniqueRecommendations) {
      const feedbackQuery = `
        SELECT voto_feedback FROM feedback_utente 
        WHERE id_utente = ? AND id_canzone = ?
      `;
      
      const [feedbackRows] = await pool.execute(feedbackQuery, [parseInt(userId), song.id]);
      
      if (feedbackRows.length === 0 || feedbackRows[0].voto_feedback >= 3) {
        finalRecommendations.push(song);
      }
    }
    
    finalRecommendations.sort((a, b) => b.popolarita - a.popolarita);
    const shuffledRecommendations = finalRecommendations
      .sort(() => Math.random() - 0.5)
      .slice(0, limit);
    
    console.log('DEBUG: Raccomandazioni finali:', shuffledRecommendations.length);
    
    if (typeof saveToHistory === 'function' && shuffledRecommendations.length > 0) {
        await saveToHistory(parseInt(userId), shuffledRecommendations, mood);
    }
    
    const statsQuery = `
      SELECT 
        COUNT(*) as total_rated,
        AVG(voto_feedback) as avg_rating,
        COUNT(CASE WHEN voto_feedback >= 4 THEN 1 END) as liked_songs
      FROM feedback_utente 
      WHERE id_utente = ?
    `;
    
    const [statsRows] = await pool.execute(statsQuery, [userId]);

    for (const song of shuffledRecommendations) {
      const [ratingRows] = await pool.execute(
        'SELECT voto_feedback FROM feedback_utente WHERE id_utente = ? AND id_canzone = ?',
        [parseInt(userId), song.id]
      );
      
      song.userRating = ratingRows.length > 0 ? ratingRows[0].voto_feedback : 0;
      song.popolarita = parseFloat(song.popolarita) || 0.0;
    }
    
    res.json({
      recommendations: shuffledRecommendations,
      basedOn: {
        genres: genres,
        mood: mood
      },
      userStats: statsRows[0]
    });
    
  } catch (error) {
    console.error('Errore raccomandazioni:', error);
    res.status(500).json({ error: 'Errore interno del server nelle raccomandazioni' });
  }
});

app.get('/api/users/:userId/history', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const mood = req.query.mood; 
        
        let query = `
            SELECT 
                sc.id,
                sc.id_canzone,
                sc.nome_canzone,
                sc.artista,
                sc.genere,
                sc.mood_utente_al_momento,
                sc.data_raccomandazione,
                sc.ascoltata,
                sc.data_ascolto,
                sc.durata_ascolto_secondi,
                c.url_immagine_copertina,
                c.popolarita,
                fu.voto_feedback
            FROM storico_canzoni sc
            LEFT JOIN canzoni c ON sc.id_canzone = c.id
            LEFT JOIN feedback_utente fu ON sc.id_canzone = fu.id_canzone AND fu.id_utente = sc.id_utente
            WHERE sc.id_utente = ?
        `;
        
        const queryParams = [userId];
        
        if (mood) {
            query += ` AND sc.mood_utente_al_momento = ?`;
            queryParams.push(mood);
        }
        
        query += ` ORDER BY sc.data_raccomandazione DESC LIMIT ${limit} OFFSET ${offset}`;
        
        const [history] = await pool.execute(query, queryParams);
        
        let countQuery = `SELECT COUNT(*) as total FROM storico_canzoni WHERE id_utente = ?`;
        const countParams = [userId];
        
        if (mood) {
            countQuery += ` AND mood_utente_al_momento = ?`;
            countParams.push(mood);
        }
        
        const [countRows] = await pool.execute(countQuery, countParams);
        
        const statsQuery = `
            SELECT 
                COUNT(*) as total_recommendations,
                COUNT(CASE WHEN ascoltata = TRUE THEN 1 END) as songs_listened,
                AVG(durata_ascolto_secondi) as avg_listen_duration,
                mood_utente_al_momento,
                COUNT(*) as recommendations_per_mood
            FROM storico_canzoni 
            WHERE id_utente = ?
            GROUP BY mood_utente_al_momento
        `;
        
        const [statsRows] = await pool.execute(statsQuery, [userId]);
        
        res.json({
            history: history,
            pagination: {
                total: countRows[0].total,
                limit: limit,
                offset: offset,
                hasMore: (offset + limit) < countRows[0].total
            },
            stats: {
                moodBreakdown: statsRows,
                totalRecommendations: countRows[0].total
            }
        });
        
    } catch (error) {
        console.error('Errore recupero storico:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.put('/api/users/:userId/history/:songId/listened', authenticateToken, async (req, res) => {
    try {
        const { userId, songId } = req.params;
        const { duration } = req.body; 
        
        const query = `
            UPDATE storico_canzoni 
            SET ascoltata = TRUE, 
                data_ascolto = NOW(),
                durata_ascolto_secondi = ?
            WHERE id_utente = ? AND id_canzone = ?
            ORDER BY data_raccomandazione DESC 
            LIMIT 1
        `;
        
        const [result] = await pool.execute(query, [duration || 0, userId, songId]);
        
        if (result.affectedRows > 0) {
            res.json({ 
                message: 'Canzone segnata come ascoltata',
                listened: true 
            });
        } else {
            res.status(404).json({ error: 'Record non trovato nello storico' });
        }
        
    } catch (error) {
        console.error('Errore aggiornamento ascolto:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.get('/api/users/:userId/history/stats', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const statsQuery = `
            SELECT 
                COUNT(*) as total_recommendations,
                COUNT(CASE WHEN ascoltata = TRUE THEN 1 END) as total_listened,
                ROUND(COUNT(CASE WHEN ascoltata = TRUE THEN 1 END) * 100.0 / COUNT(*), 2) as listen_rate,
                AVG(durata_ascolto_secondi) as avg_listen_duration,
                COUNT(DISTINCT DATE(data_raccomandazione)) as days_active,
                MIN(data_raccomandazione) as first_recommendation,
                MAX(data_raccomandazione) as last_recommendation
            FROM storico_canzoni 
            WHERE id_utente = ?
        `;
        
        const [stats] = await pool.execute(statsQuery, [userId]);
        
        const genreQuery = `
            SELECT genere, COUNT(*) as count
            FROM storico_canzoni
            WHERE id_utente = ?
            GROUP BY genere
            ORDER BY count DESC
            LIMIT 5
        `;
        
        const [topGenres] = await pool.execute(genreQuery, [userId]);
        
        const moodQuery = `
            SELECT mood_utente_al_momento, COUNT(*) as count
            FROM storico_canzoni
            WHERE id_utente = ?
            GROUP BY mood_utente_al_momento
            ORDER BY count DESC
        `;
        
        const [moodStats] = await pool.execute(moodQuery, [userId]);
        
        res.json({
            overall: stats[0],
            topGenres: topGenres,
            moodBreakdown: moodStats
        });
        
    } catch (error) {
        console.error('Errore statistiche storico:', error);
        res.status(500).json({ error: 'Errore interno del server' });
    }
});

app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:5500'],
  credentials: true
}));

// Gestione errori globale
app.use((error, req, res, next) => {
  console.error('Errore non gestito:', error);
  res.status(500).json({ error: 'Errore interno del server' });
});

// Gestione route non trovate
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint non trovato' });
});

// Avvio server
const server = app.listen(port, () => {
  console.log(`Server in ascolto sulla porta ${port}`);
});

// Gestione shutdown graceful
process.on('SIGTERM', () => {
  console.log('Ricevuto SIGTERM, chiudendo server...');
  server.close(() => {
    console.log('Server chiuso');
    pool.end();
  });
});

process.on('SIGINT', () => {
  console.log('Ricevuto SIGINT, chiudendo server...');
  server.close(() => {
    console.log('Server chiuso');
    pool.end();
  });
});

function validatePasswordServer(password) {
  const errors = [];
  
  if (password.length < 8) {
    errors.push('• Deve essere lunga almeno 8 caratteri');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('• Deve contenere almeno una lettera maiuscola');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('• Deve contenere almeno una lettera minuscola');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('• Deve contenere almeno un numero');
  }
  
  if (!/[^A-Za-z0-9]/.test(password)) {
    errors.push('• Deve contenere almeno un carattere speciale (!@#$%^&* ecc.)');
  }
  
  return errors;
}

module.exports = app;