/**
 * Noise-Resilient Response Analyzer
 * 
 * Normalizes responses by removing:
 * - Timestamps
 * - Session identifiers
 * - Ads and tracking pixels
 * - Dynamic blocks
 * 
 * Performs structural/semantic analysis instead of raw string matching.
 */

/**
 * Response normalization result
 */
export interface NormalizedResponse {
  original: string;
  normalized: string;
  removedElements: string[];
  structuralFingerprint: string;
  semanticTokens: string[];
}

/**
 * Response comparison result
 */
export interface ComparisonResult {
  similarity: number; // 0.0 to 1.0
  isDifferent: boolean;
  differenceScore: number;
  structuralDifference: boolean;
  semanticDifference: boolean;
  details: string[];
}

/**
 * Noise-Resilient Response Analyzer
 */
export class ResponseAnalyzer {
  private timestampPatterns: RegExp[] = [
    /\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/g, // ISO timestamps
    /\d{10,13}/g, // Unix timestamps
    /\d{1,2}\/\d{1,2}\/\d{2,4}/g, // Date formats
    /\d{1,2}:\d{2}(:\d{2})?(\s?[AP]M)?/gi, // Time formats
  ];

  private sessionIdPatterns: RegExp[] = [
    /session[_-]?id[=:]\w+/gi,
    /PHPSESSID[=:]\w+/gi,
    /jsessionid[=:]\w+/gi,
    /asp\.net_sessionid[=:]\w+/gi,
    /sid[=:]\w{20,}/gi,
    /token[=:]\w{20,}/gi,
    /csrf[_-]?token[=:]\w+/gi,
  ];

  private dynamicPatterns: RegExp[] = [
    /<script[^>]*>[\s\S]*?<\/script>/gi, // Scripts
    /<style[^>]*>[\s\S]*?<\/style>/gi, // Styles
    /<!--[\s\S]*?-->/g, // HTML comments
    /<noscript[^>]*>[\s\S]*?<\/noscript>/gi,
    /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
  ];

  private adPatterns: RegExp[] = [
    /google[_-]?analytics/gi,
    /googletagmanager/gi,
    /facebook\.com\/tr/gi,
    /doubleclick\.net/gi,
    /<ins[^>]*class=['"]*adsbygoogle/gi,
  ];

  /**
   * Normalize response by removing noise
   */
  normalize(response: string): NormalizedResponse {
    let normalized = response;
    const removedElements: string[] = [];

    // Remove timestamps
    for (const pattern of this.timestampPatterns) {
      const matches = normalized.match(pattern);
      if (matches) {
        removedElements.push(`Timestamps: ${matches.length}`);
        normalized = normalized.replace(pattern, "[TIMESTAMP]");
      }
    }

    // Remove session IDs
    for (const pattern of this.sessionIdPatterns) {
      const matches = normalized.match(pattern);
      if (matches) {
        removedElements.push(`Session IDs: ${matches.length}`);
        normalized = normalized.replace(pattern, "[SESSION_ID]");
      }
    }

    // Remove dynamic content
    for (const pattern of this.dynamicPatterns) {
      const matches = normalized.match(pattern);
      if (matches) {
        removedElements.push(`Dynamic blocks: ${matches.length}`);
        normalized = normalized.replace(pattern, "");
      }
    }

    // Remove ads and tracking
    for (const pattern of this.adPatterns) {
      const matches = normalized.match(pattern);
      if (matches) {
        removedElements.push(`Ad/tracking elements: ${matches.length}`);
        normalized = normalized.replace(pattern, "");
      }
    }

    // Remove excessive whitespace
    normalized = normalized.replace(/\s+/g, " ").trim();

    // Generate structural fingerprint
    const structuralFingerprint = this.generateStructuralFingerprint(normalized);

    // Extract semantic tokens
    const semanticTokens = this.extractSemanticTokens(normalized);

    return {
      original: response,
      normalized,
      removedElements,
      structuralFingerprint,
      semanticTokens,
    };
  }

  /**
   * Compare two responses
   */
  compare(
    response1: string,
    response2: string,
    threshold: number = 0.15 // 15% difference threshold
  ): ComparisonResult {
    // Normalize both responses
    const norm1 = this.normalize(response1);
    const norm2 = this.normalize(response2);

    const details: string[] = [];

    // Compare structural fingerprints
    const structuralDifference =
      norm1.structuralFingerprint !== norm2.structuralFingerprint;

    if (structuralDifference) {
      details.push(
        `Structural difference detected: ${norm1.structuralFingerprint} vs ${norm2.structuralFingerprint}`
      );
    }

    // Compare semantic tokens
    const tokenSimilarity = this.compareTokens(
      norm1.semanticTokens,
      norm2.semanticTokens
    );

    const semanticDifference = tokenSimilarity < (1 - threshold);

    if (semanticDifference) {
      details.push(
        `Semantic similarity: ${(tokenSimilarity * 100).toFixed(1)}%`
      );
    }

    // Calculate string similarity on normalized text
    const stringSimilarity = this.calculateLevenshteinSimilarity(
      norm1.normalized,
      norm2.normalized
    );

    details.push(
      `String similarity: ${(stringSimilarity * 100).toFixed(1)}%`
    );

    // Calculate overall similarity (weighted average)
    const similarity =
      stringSimilarity * 0.5 + tokenSimilarity * 0.3 + (structuralDifference ? 0 : 0.2);

    const differenceScore = 1 - similarity;
    const isDifferent = differenceScore > threshold;

    return {
      similarity,
      isDifferent,
      differenceScore,
      structuralDifference,
      semanticDifference,
      details,
    };
  }

  /**
   * Generate structural fingerprint (HTML structure hash)
   */
  private generateStructuralFingerprint(html: string): string {
    // Extract tag structure only
    const tags = html.match(/<\/?[a-z][a-z0-9]*\b[^>]*>/gi) || [];
    const structure = tags
      .map(tag => tag.match(/<\/?([a-z][a-z0-9]*)/i)?.[1])
      .filter(Boolean)
      .join(",");

    // Simple hash
    let hash = 0;
    for (let i = 0; i < structure.length; i++) {
      const char = structure.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }

    return hash.toString(16);
  }

  /**
   * Extract semantic tokens (meaningful words)
   */
  private extractSemanticTokens(text: string): string[] {
    // Remove HTML tags
    const cleanText = text.replace(/<[^>]*>/g, " ");

    // Extract words (alphanumeric sequences)
    const words = cleanText.match(/\w+/g) || [];

    // Filter out noise words
    const noiseWords = new Set([
      "the",
      "a",
      "an",
      "and",
      "or",
      "but",
      "in",
      "on",
      "at",
      "to",
      "for",
      "of",
      "with",
      "by",
      "from",
      "up",
      "about",
      "into",
      "through",
      "during",
      "is",
      "are",
      "was",
      "were",
      "be",
      "been",
      "being",
      "have",
      "has",
      "had",
      "do",
      "does",
      "did",
      "will",
      "would",
      "could",
      "should",
      "may",
      "might",
      "must",
      "can",
    ]);

    const meaningfulWords = words
      .map(w => w.toLowerCase())
      .filter(w => w.length > 2 && !noiseWords.has(w));

    // Remove duplicates and sort
    return Array.from(new Set(meaningfulWords)).sort();
  }

  /**
   * Compare semantic token sets
   */
  private compareTokens(tokens1: string[], tokens2: string[]): number {
    if (tokens1.length === 0 && tokens2.length === 0) return 1.0;
    if (tokens1.length === 0 || tokens2.length === 0) return 0.0;

    const set1 = new Set(tokens1);
    const set2 = new Set(tokens2);

    // Jaccard similarity
    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return intersection.size / union.size;
  }

  /**
   * Calculate Levenshtein similarity between two strings
   */
  private calculateLevenshteinSimilarity(s1: string, s2: string): number {
    if (s1 === s2) return 1.0;
    if (s1.length === 0 || s2.length === 0) return 0.0;

    // Limit comparison to first 1000 characters for performance
    const str1 = s1.substring(0, 1000);
    const str2 = s2.substring(0, 1000);

    const distance = this.levenshteinDistance(str1, str2);
    const maxLen = Math.max(str1.length, str2.length);

    return 1 - distance / maxLen;
  }

  /**
   * Calculate Levenshtein distance
   */
  private levenshteinDistance(s1: string, s2: string): number {
    const len1 = s1.length;
    const len2 = s2.length;
    const matrix: number[][] = [];

    for (let i = 0; i <= len1; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= len2; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1, // deletion
          matrix[i][j - 1] + 1, // insertion
          matrix[i - 1][j - 1] + cost // substitution
        );
      }
    }

    return matrix[len1][len2];
  }

  /**
   * Detect SQL error patterns in response
   */
  detectSQLError(response: string): {
    detected: boolean;
    errorType?: string;
    evidence?: string;
  } {
    const sqlErrorPatterns = [
      { type: "MySQL", pattern: /you have an error in your sql syntax/i },
      { type: "MySQL", pattern: /warning: mysql/i },
      { type: "PostgreSQL", pattern: /warning: pg_/i },
      { type: "PostgreSQL", pattern: /postgresql.*error/i },
      { type: "MSSQL", pattern: /microsoft sql server/i },
      { type: "MSSQL", pattern: /odbc sql server driver/i },
      { type: "Oracle", pattern: /ora-\d{5}/i },
      { type: "SQLite", pattern: /sqlite3?::/i },
      { type: "Generic", pattern: /sql syntax.*error/i },
      { type: "Generic", pattern: /unclosed quotation mark/i },
    ];

    for (const { type, pattern } of sqlErrorPatterns) {
      const match = response.match(pattern);
      if (match) {
        return {
          detected: true,
          errorType: type,
          evidence: match[0],
        };
      }
    }

    return { detected: false };
  }
}
