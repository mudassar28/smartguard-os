"use server";
import { GoogleGenerativeAI } from "@google/generative-ai";

export async function analyzeContract(contractCode: string): Promise<string> {
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY!);

  // NOTE: responseMimeType is intentionally removed here.
  // The page's parseAuditJSON already handles JSON extraction robustly
  // (strips fences, finds first/last braces, etc.). Forcing application/json
  // can cause the model to silently truncate long responses on complex contracts.
  const model = genAI.getGenerativeModel({
    model: "gemini-2.5-flash",
  });

  const prompt = `You are an expert Solidity smart contract security auditor. Analyze the contract below and respond ONLY with a single JSON object — no markdown fences, no preamble, no explanation. Start your response with { and end with }.

REQUIRED JSON SCHEMA:
{
  "riskScore": <integer 0-100, overall risk>,
  "counts": {
    "critical": <integer>,
    "high": <integer>,
    "medium": <integer>,
    "low": <integer>
  },
  "executive": "<3-5 paragraph non-technical summary for a CTO: contract purpose, risk level, top 3 concerns>",
  "vulnerabilities": "<technical breakdown — for each issue use ## VULNERABILITY NAME\\n**Severity:** ...\\n**Location:** ...\\n**Description:** ...\\n**Impact:** ...>",
  "redTeam": "<numbered step-by-step attack path showing exactly how a hacker would exploit each vulnerability>",
  "remediation": "<for each vulnerability show the vulnerable code block then the safe replacement using markdown code blocks with solidity syntax highlighting>"
}

SCORING GUIDE:
- 0-24: Low risk (minor issues only)
- 25-49: Medium risk (some exploitable issues)
- 50-74: High risk (serious vulnerabilities)
- 75-100: Critical risk (contract is likely exploitable / funds at risk)

AUDIT CHECKLIST — check for all of the following:
- Reentrancy (single and cross-function)
- Integer overflow / underflow (especially in Solidity <0.8.0)
- Access control issues (missing onlyOwner, tx.origin usage)
- Unchecked external call return values
- Unprotected selfdestruct or delegatecall
- Front-running / transaction ordering vulnerabilities
- Timestamp dependence
- Gas limit and loops (denial-of-service vectors)
- Hardcoded addresses or credentials
- Missing event emissions on state changes
- Centralization risks (single admin key)
- Flash loan attack surface
- Price oracle manipulation
- Unsafe ERC-20 interactions (missing return value checks)

INPUT CONTRACT:
\`\`\`solidity
${contractCode}
\`\`\`

REMINDER: Your ENTIRE response must be ONLY the JSON object. Start with { and end with }. No text before or after.`;

  const result = await model.generateContent(prompt);
  return result.response.text();
}
