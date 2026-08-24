// ---------------------------------------------------------------------------
// TypeScript types mirroring API response shapes.
// Manual definitions — no code generation. Keep in sync with api.py.
// ---------------------------------------------------------------------------

// --- Advisory ---

export interface Advisory {
  id: number;
  advisory_id: string;
  type: string;
  source: string;
  original_source: string | null;
  title: string | null;
  pub_date: string | null;
  extraction_status: string;
  triage_status: string;
  first_seen: string;
}

export interface AdvisoryDetail extends Advisory {
  summary: string | null;
  link: string | null;
  article_body: string | null;
  enriched_body: string | null;
  extracted_json: string | null;
  extraction_model: string | null;
  extraction_error: string | null;
  extracted_at: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  llm_latency_ms: number | null;
  llm_cost_usd: number | null;
  ioc_count: number;
  detection_rule_count: number;
  technique_count: number;
  d3fend_count: number;
  asset_count: number;
  cve_count: number;
  sectors: string[];
  actors: string[];
  malware: string[];
  behavior_count: number;
  extraction_issues: { warning_count: number; error_count: number };
}

// --- Pagination ---

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

// --- Stats ---

export interface StatsResponse {
  advisories: {
    total: number;
    by_source: Record<string, number>;
    by_extraction: Record<string, number>;
    by_triage?: Record<string, number>;
  };
  polls: Record<string, string | null>;
  msrc?: MsrcStatsResponse;
}

// --- LLM Telemetry ---

export interface LlmStats {
  call_count: number;
  total_cost: number;
  total_input_tokens: number;
  total_output_tokens: number;
  avg_cost_per_advisory: number;
  calls_by_phase: Record<string, number>;
}

// --- Analysis phase (ADVISORY_ANALYSIS.md schema) ---
// New-schema interfaces added in WS-12 Phase B for dual-schema support.

export interface ExecutionReference {
  type: 'atomic_red_team' | 'tool' | 'sigma_rule';
  id: string | null;
  name: string;
}

export interface SuccessCriteriaTiered {
  basic: string;
  intermediate: string;
  advanced: string;
}

export interface DefensiveFinding {
  type: 'incident_lessons' | 'capability_gaps';
  finding: string;
  impact?: string;
  recommendation?: string;
  defensive_control_bypassed?: string;
  detection_opportunity?: string;
}

export interface RedTeamActivity {
  title: string;
  description: string;
  mitre_technique?: string;        // old schema (singular)
  mitre_techniques?: string[];     // new schema (array)
  mitre_tactic?: string;
  objective: string;
  tools?: string[];                // old schema
  execution_references?: ExecutionReference[];  // new schema
  priority: 'critical' | 'high' | 'medium';
  validation_warning?: 'malformed_id' | 'not_in_local_database';
}

export interface BlueTeamActivity {
  title: string;
  description: string;
  gap_from_advisory?: string;           // old schema
  gap_quote?: string;                   // new schema
  gap_interpretation?: string;          // new schema
  gap_quote_verified?: boolean;         // post-processing annotation
  mitre_techniques?: string[];          // new schema
  detection_rule_refs?: string[];       // new schema
  validation_method: string;
  priority: 'critical' | 'high' | 'medium';
  validation_warning?: 'malformed_id' | 'not_in_local_database';
}

export interface PurpleTeamExercise {
  title: string;
  red_action: string;
  blue_measures: string[];
  mitre_techniques: string[];
  success_criteria: string | SuccessCriteriaTiered;
  detection_rule_refs?: string[];
  kill_chain_phase?: number;
  validation_warning?: 'malformed_id' | 'not_in_local_database';
}

export interface LessonLearned {
  finding: string;
  impact: string;
  recommendation: string;
}

export interface SecurityPostureItem {
  category: string;
  title: string;
  description: string;
  gap_from_advisory?: string;
  gap_quote?: string;
  gap_interpretation?: string;
  gap_quote_verified?: boolean;
  so_what?: string;
  framework_refs?: string[];      // was required, now optional
  priority: 'critical' | 'high' | 'medium';
  maturity_level: 'foundational' | 'intermediate' | 'advanced';
}

export interface AnalysisResult {
  advisory_id: string;
  analysis_type: string;
  analysis: {
    tactical: {
      red_team_activities: RedTeamActivity[];
      blue_team_activities: BlueTeamActivity[];
      purple_team_exercises: PurpleTeamExercise[];
      lessons_learned?: LessonLearned[];
      defensive_findings?: DefensiveFinding[];
    };
    strategic: {
      security_posture: SecurityPostureItem[];
    };
  };
  model: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  latency_ms: number | null;
  cost_usd: number | null;
  created_at: string;
  cached?: boolean;
  prompt_version?: number | null;
  stale?: boolean;
  stale_reason?: string | null;
}

// --- Triage ---

export type TriageStatus = 'unread' | 'reviewed' | 'flagged';

// --- MSRC CVEs ---

export interface MsrcCve {
  cve_id: string;
  title: string | null;
  component: string | null;
  component_category: string | null;
  impact: string | null;
  severity: string | null;
  cvss_base: number | null;
  defense_score: number;
  priority: string;
  released: string | null;
  exploited_wild: boolean;
  publicly_disclosed: boolean;
  kev_listed: boolean;
  customer_action: string | null;
  cwe_id: string | null;
  cwe_description: string | null;
  advisory_ids: { id: number; advisory_id: string }[];
  vr_score: number;
  vr_priority: string;
  vr_tags: string[];
}

export interface KbEntry {
  kb_number: string;
  product_name: string | null;
  download_url: string | null;
}

export interface KevInfo {
  cve_id: string;
  vendor: string | null;
  product: string | null;
  vulnerability_name: string | null;
  date_added: string | null;
  due_date: string | null;
  known_ransomware: string | null;
  notes: string | null;
}

export interface ScoreBreakdownItem {
  name?: string;
  id?: string;
  type?: string;
  value?: string;
  description?: string;
  score: number;
}

export interface ScoreBreakdown {
  component: ScoreBreakdownItem;
  cwe: ScoreBreakdownItem;
  impact: ScoreBreakdownItem;
  attack_vector: ScoreBreakdownItem;
  privileges: ScoreBreakdownItem;
  user_interaction: ScoreBreakdownItem;
  bonuses: { name: string; score: number }[];
  total: number;
  priority: string;
}

export interface VrScoreBreakdown {
  component: ScoreBreakdownItem;
  cwe: ScoreBreakdownItem;
  impact: ScoreBreakdownItem;
  attack_vector: ScoreBreakdownItem;
  privileges: ScoreBreakdownItem;
  user_interaction: ScoreBreakdownItem;
  bonuses: { name: string; score: number }[];
  penalties: { name: string; score: number }[];
  total: number;
  priority: string;
}

export interface RelatedCve {
  cve_id: string;
  title: string | null;
  impact: string | null;
  severity: string | null;
  cwe_id: string | null;
  released: string | null;
  defense_score: number;
  priority: string;
  vr_score: number;
  vr_priority: string;
  exploited_wild: boolean;
  publicly_disclosed: boolean;
}

export interface MsrcCveDetail extends MsrcCve {
  has_kb_entries: boolean;
  description: string | null;
  cvss_temporal: number | null;
  cvss_vector: string | null;
  av: string | null;
  ac: string | null;
  pr: string | null;
  ui: string | null;
  scope: string | null;
  cwe_id: string | null;
  cwe_description: string | null;
  exploit_status: string | null;
  customer_action: string | null;
  first_seen: string | null;
  last_updated: string | null;
  kb_entries: KbEntry[];
  kev: KevInfo | null;
  advisories: { id: number; advisory_id: string; title: string | null; source: string; pub_date: string | null }[];
  score_breakdown: ScoreBreakdown;
  vr_score_breakdown: VrScoreBreakdown;
  vr_tags: string[];
  related_cves: RelatedCve[];
}

export interface MsrcStatsResponse {
  total_cves: number;
  by_priority: Record<string, number>;
  by_vr_priority: Record<string, number>;
  by_impact: Record<string, number>;
  by_severity: Record<string, number>;
  kev_count: number;
  exploited_count: number;
  last_poll: string | null;
}

// --- Extraction artifacts ---

export interface Ioc {
  id: number;
  advisory_id: string;
  type: string;
  value: string;
  context: string | null;
  validation_status: string;
  source_verified: number;
  needs_review: number;
  cross_ref_count: number;
  extraction_source: 'parse' | 'intel';
}

export interface DetectionRule {
  id: number;
  advisory_id: string;
  rule_name: string | null;
  rule_format: 'yara' | 'sigma' | 'snort';
  rule_text: string;
  validation_status: string | null;
  validation_error: string | null;
}

export interface Behavior {
  id: number;
  advisory_id: string;
  description: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  confidence: string;
}

// Advisory CVE row from GET /api/advisories/{id}/cves.
// Counts ALL advisory CVEs (non-Microsoft included). MSRC-specific fields are
// only populated when is_msrc is true; route to /msrc/{id} when is_msrc, else NVD.
export interface AdvisoryCve {
  cve_id: string;
  link_source: string | null;
  is_msrc: boolean;
  title: string | null;
  severity: string | null;
  defense_score: number;
  priority: string | null;
  kev_listed: boolean;
}

export interface AttackTechnique {
  advisory_id: string;
  technique_id: string;
  tactic: string | null;
  name: string | null;
  use_description: string | null;
  confidence: string;
  framework: 'attack' | 'd3fend';
}

export interface AdvisoryAsset {
  id: number;
  advisory_id: string;
  asset_type: string;
  original_url: string;
  local_path: string | null;
  url: string | null;
  caption: string | null;
  download_status: string;
}

export interface ExtractionLogEntry {
  id: number;
  advisory_id: string;
  extractor: string;
  severity: 'warning' | 'error';
  message: string;
  context: string | null;
  logged_at: string;
}

export type ExtractionGroup = 'ready' | 'processing' | 'issues' | 'skipped';

export const STATUS_DISPLAY_MAP: Record<string, { label: string; color: string; tooltip: string }> = {
  pending: { label: 'Pending', color: 'gray', tooltip: 'Awaiting extraction' },
  parse_done: { label: 'Parsed', color: 'blue', tooltip: 'HTML parsed, awaiting LLM extraction' },
  parse_partial: { label: 'Partial', color: 'amber', tooltip: 'HTML parsed with warnings' },
  parse_failed: { label: 'Parse Error', color: 'red', tooltip: 'HTML parsing failed' },
  completed: { label: 'Done', color: 'green', tooltip: 'Fully extracted' },
  failed: { label: 'Failed', color: 'red', tooltip: 'LLM extraction failed' },
  skipped: { label: 'Skipped', color: 'gray', tooltip: 'No article body available' },
};

// --- Cross-advisory IOC Search (WS-10) ---

export interface IocSearchItem {
  type: string;
  value: string;
  validation_status: string;
  source_verified: number;
  first_seen: string | null;
  last_seen: string | null;
  cross_ref_count: number;
  advisory_id_list: string;
  advisory_numeric_ids: string;
}

export interface IocSearchQuery {
  original: string;
  normalized: string;
  detected_type: string | null;
}

export interface IocSearchResponse {
  items: IocSearchItem[];
  total: number;
  page: number;
  per_page: number;
  query?: IocSearchQuery;
}

export interface IocStatsResponse {
  total_iocs: number;
  by_type: Record<string, number>;
  advisories_with_iocs: number;
  cross_referenced: number;
}

export interface IocAdvisoryDetail {
  id: number;
  advisory_id: string;
  title: string | null;
  source: string;
  pub_date: string | null;
  context: string | null;
  validation_status: string;
  source_verified: number;
  needs_review: number;
  actors: string[];
  malware: string[];
}
