export type EncodingType = 
  | "none"
  | "url"
  | "double_url"
  | "base64"
  | "hex"
  | "unicode"
  | "null_byte"
  | "mixed_case"
  | "comment_split"
  | "char_encoding";

export interface TampingConfig {
  enableMutations: boolean;
  enableMultiEncoding: boolean;
  mutationVariants: number;
}

export const DEFAULT_TAMPING_CONFIG: TampingConfig = {
  enableMutations: true,
  enableMultiEncoding: true,
  mutationVariants: 3,
};

const SQL_KEYWORDS = [
  "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
  "WHERE", "FROM", "AND", "OR", "ORDER", "BY", "LIMIT",
  "OFFSET", "GROUP", "HAVING", "JOIN", "ON", "INTO", "VALUES",
  "SET", "NULL", "TRUE", "FALSE", "LIKE", "IN", "BETWEEN",
  "EXISTS", "CASE", "WHEN", "THEN", "ELSE", "END", "AS",
  "TABLE", "DATABASE", "SCHEMA", "INDEX", "CREATE", "ALTER",
  "TRUNCATE", "EXEC", "EXECUTE", "WAITFOR", "DELAY", "SLEEP",
  "BENCHMARK", "EXTRACTVALUE", "UPDATEXML", "LOAD_FILE",
];

export function applyTamping(payload: string, config: TampingConfig = DEFAULT_TAMPING_CONFIG): string[] {
  const results: string[] = [payload];
  
  if (!config.enableMutations) return results;
  
  for (let i = 0; i < config.mutationVariants; i++) {
    results.push(mutatePayload(payload, i));
  }
  
  return [...new Set(results)];
}

export function mutatePayload(payload: string, seed: number = 0): string {
  let mutated = payload;
  
  const mutationType = seed % 6;
  
  switch (mutationType) {
    case 0:
      mutated = mutateEquality(mutated);
      break;
    case 1:
      mutated = mutateNumbers(mutated);
      break;
    case 2:
      mutated = mutateWhitespace(mutated);
      break;
    case 3:
      mutated = mutateComments(mutated);
      break;
    case 4:
      mutated = mutateKeywordCase(mutated);
      break;
    case 5:
      mutated = mutateQuotes(mutated);
      break;
  }
  
  return mutated;
}

function mutateEquality(payload: string): string {
  const replacements: [RegExp, string[]][] = [
    [/1\s*=\s*1/g, ["2=2", "3=3", "5=5", "0x31=0x31", "'a'='a'"]],
    [/1\s*=\s*0/g, ["2=3", "5=6", "0x31=0x32", "'a'='b'"]],
    [/AND\s+1\s*=\s*1/gi, ["AND 5=5", "AND 0x1=0x1", "AND 'x'='x'"]],
    [/OR\s+1\s*=\s*1/gi, ["OR 5=5", "OR 0x1=0x1", "OR 'x'='x'"]],
  ];
  
  let result = payload;
  for (const [pattern, options] of replacements) {
    if (pattern.test(result)) {
      const replacement = options[Math.floor(Math.random() * options.length)];
      result = result.replace(pattern, replacement);
      break;
    }
  }
  
  return result;
}

function mutateNumbers(payload: string): string {
  return payload.replace(/(\d+)/g, (match) => {
    const num = parseInt(match, 10);
    const variants = [
      match,
      `0x${num.toString(16)}`,
      `(${match})`,
      `${num}.0`,
      `CHAR(${match.split('').map(c => c.charCodeAt(0)).join(',')})`,
    ];
    return variants[Math.floor(Math.random() * variants.length)];
  });
}

function mutateWhitespace(payload: string): string {
  const whitespaceVariants = [
    " ",
    "/**/",
    "%20",
    "+",
    "\t",
    "%09",
    "%0a",
    "%0d",
  ];
  
  return payload.replace(/ /g, () => {
    return whitespaceVariants[Math.floor(Math.random() * whitespaceVariants.length)];
  });
}

function mutateComments(payload: string): string {
  const commentStyles = [
    { start: "/*", end: "*/" },
    { start: "/*!50000", end: "*/" },
    { start: "/*!32302", end: "*/" },
    { start: "#", end: "" },
  ];
  
  let result = payload;
  
  for (const keyword of SQL_KEYWORDS) {
    const regex = new RegExp(`\\b${keyword}\\b`, "gi");
    if (regex.test(result) && Math.random() > 0.5) {
      const style = commentStyles[Math.floor(Math.random() * commentStyles.length)];
      if (keyword.length > 2) {
        const midpoint = Math.floor(keyword.length / 2);
        const wrapped = keyword.slice(0, midpoint) + style.start + style.end + keyword.slice(midpoint);
        result = result.replace(regex, wrapped);
        break;
      }
    }
  }
  
  return result;
}

function mutateKeywordCase(payload: string): string {
  let result = payload;
  
  for (const keyword of SQL_KEYWORDS) {
    const regex = new RegExp(`\\b${keyword}\\b`, "gi");
    result = result.replace(regex, (match) => {
      return match.split('').map((char, i) => 
        i % 2 === 0 ? char.toLowerCase() : char.toUpperCase()
      ).join('');
    });
  }
  
  return result;
}

function mutateQuotes(payload: string): string {
  const quoteVariants = ["'", "''", "\\'", "%27", "0x27"];
  return payload.replace(/'/g, () => {
    return quoteVariants[Math.floor(Math.random() * quoteVariants.length)];
  });
}

export function applyMultiEncoding(payload: string, encodingTypes: EncodingType[]): string[] {
  const results: string[] = [payload];
  
  for (const encoding of encodingTypes) {
    results.push(encodePayload(payload, encoding));
  }
  
  results.push(encodePayload(encodePayload(payload, "url"), "url"));
  
  results.push(encodePayload(encodePayload(payload, "base64"), "url"));
  
  return [...new Set(results.filter(r => r.length > 0))];
}

export function encodePayload(payload: string, encoding: EncodingType): string {
  switch (encoding) {
    case "none":
      return payload;
      
    case "url":
      return encodeURIComponent(payload);
      
    case "double_url":
      return encodeURIComponent(encodeURIComponent(payload));
      
    case "base64":
      return Buffer.from(payload).toString("base64");
      
    case "hex":
      return "0x" + Buffer.from(payload).toString("hex");
      
    case "unicode":
      return toUnicodeEscape(payload);
      
    case "null_byte":
      return payload + "%00";
      
    case "mixed_case":
      return toMixedCase(payload);
      
    case "comment_split":
      return toCommentSplit(payload);
      
    case "char_encoding":
      return toCharEncoding(payload);
      
    default:
      return payload;
  }
}

function toUnicodeEscape(payload: string): string {
  return payload.split('').map(char => {
    const code = char.charCodeAt(0);
    if (code > 127 || /[a-zA-Z]/.test(char)) {
      return `%u00${code.toString(16).padStart(2, '0')}`;
    }
    return char;
  }).join('');
}

function toMixedCase(payload: string): string {
  let result = payload;
  for (const keyword of SQL_KEYWORDS) {
    const regex = new RegExp(`\\b${keyword}\\b`, "gi");
    result = result.replace(regex, (match) => {
      return match.split('').map((char, i) => 
        i % 2 === 0 ? char.toLowerCase() : char.toUpperCase()
      ).join('');
    });
  }
  return result;
}

function toCommentSplit(payload: string): string {
  let result = payload;
  for (const keyword of SQL_KEYWORDS) {
    const regex = new RegExp(`\\b${keyword}\\b`, "gi");
    result = result.replace(regex, (match) => {
      if (match.length <= 2) return match;
      const midpoint = Math.floor(match.length / 2);
      return match.slice(0, midpoint) + "/**/" + match.slice(midpoint);
    });
  }
  return result;
}

function toCharEncoding(payload: string): string {
  const chars = payload.split('');
  const encoded = chars.map(c => `CHAR(${c.charCodeAt(0)})`).join('+');
  return `CONCAT(${encoded})`;
}

export const ALL_ENCODINGS: EncodingType[] = [
  "none", "url", "double_url", "base64", "hex", 
  "unicode", "null_byte", "mixed_case", "comment_split"
];

export function generatePayloadVariants(
  basePayload: string,
  config: TampingConfig = DEFAULT_TAMPING_CONFIG
): string[] {
  const variants: string[] = [];
  
  const tamped = applyTamping(basePayload, config);
  
  if (config.enableMultiEncoding) {
    for (const tampedPayload of tamped) {
      const encoded = applyMultiEncoding(tampedPayload, ALL_ENCODINGS.slice(0, 5));
      variants.push(...encoded);
    }
  } else {
    variants.push(...tamped);
  }
  
  return [...new Set(variants)];
}
