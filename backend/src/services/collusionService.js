const crypto = require('node:crypto');

/**
 * Collusion-Resistant Fingerprinting & Traitor Tracing Service
 * 
 * Implements:
 * 1. Tardos-style Collusion-Secure Fingerprinting Codes:
 *    - Each recipient receives a distinct m-bit codeword generated from bias vector P.
 *    - Even when a coalition of 'c' colluders combine, differ, or randomize their copies,
 *      the accusation algorithm reliably identifies the colluders with provable statistical confidence.
 * 2. HKDF Session-Bound Ephemeral Key Derivation (RFC 5869):
 *    - Binds decryption keys to docId, recipientId, and provenance sequence number.
 * 3. Forensic Watermark Embedding & Extraction:
 *    - Injects recipient fingerprint into document binary/metadata.
 * 4. Traitor Tracing & Accusation Algorithm:
 *    - Scores each candidate recipient against a leaked/hybrid watermark.
 */

// Default Tardos code length (bits)
const DEFAULT_CODE_LENGTH = 256;
const TARDOS_CUTOFF = 0.15; // Cutoff parameter to avoid extreme probability weights

/**
 * Generate a deterministic bias vector P = (p_1, ..., p_m) for a given document
 * using SHA-256 HMAC as a deterministic pseudo-random generator.
 * Each p_j is sampled uniformly in [TARDOS_CUTOFF, 1 - TARDOS_CUTOFF].
 * 
 * @param {string} docId - Unique document identifier
 * @param {number} codeLength - Number of bits in fingerprint (default: 256)
 * @returns {number[]} Array of probabilities p_j in [t, 1-t]
 */
function generateBiasVector(docId, codeLength = DEFAULT_CODE_LENGTH) {
  const biases = [];
  const key = Buffer.from(`TARDOS_BIAS_SEED:${docId}`, 'utf-8');

  for (let j = 0; j < codeLength; j++) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(`INDEX:${j}`);
    const hash = hmac.digest();
    // Read 32-bit unsigned int and normalize to [0, 1)
    const rand = hash.readUInt32BE(0) / 0xffffffff;
    // Map to [TARDOS_CUTOFF, 1 - TARDOS_CUTOFF]
    const p = TARDOS_CUTOFF + rand * (1 - 2 * TARDOS_CUTOFF);
    biases.push(p);
  }
  return biases;
}

/**
 * Generate a unique, deterministic fingerprint codeword for a recipient on a document
 * Each bit W_{i,j} is selected according to Pr[W_{i,j} = 1] = p_j.
 * 
 * @param {string} docId - Document ID
 * @param {string} recipientId - Recipient ID
 * @param {number[]} biases - Bias vector for this document
 * @returns {string} Binary string of length m (e.g. "1011001...")
 */
function generateRecipientCodeword(docId, recipientId, biases) {
  const codeLength = biases.length;
  const key = Buffer.from(`RECIPIENT_CODEWORD:${docId}:${recipientId}`, 'utf-8');
  let codeword = '';

  for (let j = 0; j < codeLength; j++) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(`BIT:${j}`);
    const hash = hmac.digest();
    const rand = hash.readUInt32BE(0) / 0xffffffff;
    codeword += rand < biases[j] ? '1' : '0';
  }
  return codeword;
}

/**
 * Symmetric Tardos accusation score function for a single bit
 * U(1, p) = sqrt((1 - p) / p)
 * U(0, p) = -sqrt(p / (1 - p))
 * 
 * @param {string|number} candidateBit - Candidate's bit ('1' or '0')
 * @param {number} p - Bias p_j for this bit position
 * @returns {number} Accusation weight
 */
function scoreFunction(candidateBit, p) {
  const bit = Number(candidateBit);
  if (bit === 1) {
    return Math.sqrt((1 - p) / p);
  } else {
    return -Math.sqrt(p / (1 - p));
  }
}

/**
 * Compute the accusation score of a candidate recipient given a leaked/suspect watermark
 * Score S_i = sum_{j=1}^m [ y_j * U(W_{i,j}, p_j) + (1 - y_j) * U(1 - W_{i,j}, 1 - p_j) ]
 * 
 * @param {string} suspectWatermark - Extracted suspect binary watermark (length m)
 * @param {string} candidateCodeword - Recipient's assigned binary codeword (length m)
 * @param {number[]} biases - Document bias vector
 * @returns {number} Accusation score S_i
 */
function computeAccusationScore(suspectWatermark, candidateCodeword, biases) {
  let score = 0;
  const m = Math.min(suspectWatermark.length, candidateCodeword.length, biases.length);

  for (let j = 0; j < m; j++) {
    const y_j = Number(suspectWatermark[j]);
    const w_ij = candidateCodeword[j];
    const p_j = biases[j];

    // If suspect bit is 1, add standard Tardos score
    if (y_j === 1) {
      score += scoreFunction(w_ij, p_j);
    } else {
      // Symmetric handling when suspect bit is 0
      score += scoreFunction(w_ij === '1' ? '0' : '1', 1 - p_j);
    }
  }

  return score;
}

/**
 * Traitor Tracing Algorithm:
 * Evaluates a leaked watermark against all candidate recipients and identifies colluders.
 * 
 * @param {Object} params
 * @param {string} params.suspectWatermark - Leaked binary watermark string
 * @param {Array<{ recipientId: string, username: string, email: string, codeword: string }>} params.candidates
 * @param {number[]} params.biases - Document bias vector
 * @returns {Object} Accusation report detailing identified colluders, scores, threshold, and confidence
 */
function traceTraitors({ suspectWatermark, candidates, biases }) {
  if (!candidates || candidates.length === 0) {
    throw new Error('Candidate list cannot be empty');
  }

  const results = candidates.map((cand) => {
    const score = computeAccusationScore(suspectWatermark, cand.codeword, biases);
    return {
      recipientId: cand.recipientId,
      username: cand.username,
      email: cand.email,
      score: Number(score.toFixed(4))
    };
  });

  // Theoretical threshold:
  // Under the Tardos model, an innocent non-colluder's expected score is 0 with standard deviation sqrt(m).
  // A threshold Z = 1.25 * sqrt(m) ensures bounded false positives while detecting colluders.
  const m = biases ? biases.length : DEFAULT_CODE_LENGTH;
  const threshold = Math.max(15.0, 1.25 * Math.sqrt(m));

  // Identify accused colluders whose scores exceed the threshold
  const accused = results
    .filter((r) => r.score >= threshold)
    .sort((a, b) => b.score - a.score);

  // Sort all candidates descending by score
  results.sort((a, b) => b.score - a.score);

  // Calculate confidence percentage
  const accusedWithConfidence = accused.map((acc) => {
    const scoreRatio = acc.score / threshold;
    const confidence = Math.min(99.99, Number((Math.min(scoreRatio, 2.5) * 45 + 10).toFixed(2)));
    return {
      ...acc,
      threshold: Number(threshold.toFixed(2)),
      confidencePercentage: confidence
    };
  });

  return {
    collusionDetected: accusedWithConfidence.length > 0,
    colluderCount: accusedWithConfidence.length,
    threshold: Number(threshold.toFixed(2)),
    accusedRecipients: accusedWithConfidence,
    rankedCandidates: results,
    analysisTimestamp: new Date().toISOString()
  };
}

/**
 * Simulate a coalition collusion attack between k colluders (for testing & demonstration)
 * Implements standard collusion strategies:
 * - 'interleaving': Randomly pick bits from among the colluders
 * - 'majority': Majority voting among colluders
 * - 'worst_case': If any colluder has '1', set '1' (or randomized coin flip on differences)
 * 
 * @param {string[]} colluderCodewords - Array of binary codewords held by colluders
 * @param {string} [strategy='interleaving'] - Collusion strategy
 * @returns {string} Forged hybrid watermark
 */
function simulateCollusion(colluderCodewords, strategy = 'interleaving') {
  if (!colluderCodewords || colluderCodewords.length === 0) {
    throw new Error('At least one colluder codeword is required');
  }

  const m = colluderCodewords[0].length;
  let hybrid = '';

  for (let j = 0; j < m; j++) {
    const bits = colluderCodewords.map((cw) => cw[j]);
    const allEqual = bits.every((b) => b === bits[0]);

    if (allEqual) {
      // Marking assumption: colluders cannot change positions where all agree
      hybrid += bits[0];
    } else {
      // Differing position: apply collusion strategy
      if (strategy === 'majority') {
        const ones = bits.filter((b) => b === '1').length;
        hybrid += ones >= bits.length / 2 ? '1' : '0';
      } else {
        // Interleaving / random choice among colluders
        const pickedIndex = Math.floor(Math.random() * bits.length);
        hybrid += bits[pickedIndex];
      }
    }
  }

  return hybrid;
}

/**
 * Derive an ephemeral session decryption key using HKDF (RFC 5869)
 * Binds the symmetric key to document ID, recipient ID, and provenance sequence number.
 * 
 * @param {Object} params
 * @param {Buffer} params.masterKey - 32-byte AES key
 * @param {string} params.docId - Document ID
 * @param {string} params.recipientId - Recipient ID
 * @param {number} params.sequenceNumber - Sequence number in provenance ledger
 * @returns {Buffer} 32-byte derived session key
 */
function deriveSessionKey({ masterKey, docId, recipientId, sequenceNumber }) {
  const salt = crypto.createHash('sha256').update(docId.toString()).digest();
  const info = Buffer.from(
    `SIH26237_SESSION_KEY|DOC:${docId}|RECIPIENT:${recipientId}|SEQ:${sequenceNumber}`,
    'utf-8'
  );

  return Buffer.from(crypto.hkdfSync('sha256', masterKey, salt, info, 32));
}

/**
 * Embed a forensic collusion-resistant fingerprint payload into document content
 * 
 * @param {Buffer} documentBuffer - Plaintext file content
 * @param {Object} metadata
 * @param {string} metadata.codeword - Recipient's binary fingerprint codeword
 * @param {string} metadata.recipientId - Recipient ID
 * @param {number} metadata.sequenceNumber - Provenance sequence number
 * @returns {Buffer} Watermarked document buffer
 */
function embedForensicFingerprint(documentBuffer, { codeword, recipientId, sequenceNumber }) {
  const payload = {
    alg: 'TARDOS-256-COLLUSION-RESISTANT',
    rec: recipientId.toString(),
    seq: sequenceNumber,
    codeword,
    ts: Date.now()
  };

  const payloadString = `\n%SIH26237_FORENSIC_WATERMARK_START%\n${JSON.stringify(payload)}\n%SIH26237_FORENSIC_WATERMARK_END%\n`;
  const watermarkBuffer = Buffer.from(payloadString, 'utf-8');

  return Buffer.concat([documentBuffer, watermarkBuffer]);
}

/**
 * Extract forensic fingerprint payload from document content
 * 
 * @param {Buffer|string} documentContent - Watermarked document content
 * @returns {{ codeword: string, recipientId: string, sequenceNumber: number } | null}
 */
function extractForensicFingerprint(documentContent) {
  const contentString = Buffer.isBuffer(documentContent)
    ? documentContent.toString('utf-8')
    : documentContent;

  const startMarker = '%SIH26237_FORENSIC_WATERMARK_START%';
  const endMarker = '%SIH26237_FORENSIC_WATERMARK_END%';

  const startIndex = contentString.indexOf(startMarker);
  const endIndex = contentString.indexOf(endMarker);

  if (startIndex === -1 || endIndex === -1 || startIndex >= endIndex) {
    return null;
  }

  const jsonString = contentString
    .slice(startIndex + startMarker.length, endIndex)
    .trim();

  try {
    return JSON.parse(jsonString);
  } catch (e) {
    return null;
  }
}

module.exports = {
  DEFAULT_CODE_LENGTH,
  generateBiasVector,
  generateRecipientCodeword,
  scoreFunction,
  computeAccusationScore,
  traceTraitors,
  simulateCollusion,
  deriveSessionKey,
  embedForensicFingerprint,
  extractForensicFingerprint
};
