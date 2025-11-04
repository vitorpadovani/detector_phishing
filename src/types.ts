export interface Signal {
  name: string;
  weight: number;
  detail: string;
}

export interface SSLInfo {
  present: boolean;
  issuer?: any;
  subject?: any;
  validFrom?: string;
  validTo?: string;
  subjectAltName?: string[];
  daysToExpire?: number | null;
  hostnameMatches?: boolean;
}

export interface ContentMeta {
  forms: number;
  hasPassword: boolean;
  loginLike: boolean;
  sensitiveForm: boolean;
  keywordsFound: string[];
  crossDomainForms: string[];
  tricks: string[];
}

export interface AnalysisResult {
  urlInput: string;
  finalUrl: string;
  domain: string;
  createdAt: string;
  riskScore: number;
  verdict: "MALICIOSA" | "SUSPEITA" | "PROVAVELMENTE SEGURA";
  signals: Signal[];
  meta: Record<string, any>;
}
