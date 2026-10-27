# Data Forensics mini project context

Recorded on 26 October 2026 at the user's request to retain the project and submission requirements for future work.

## User request and required submission

The user initially asked for review and retention, then explicitly requested implementation of the complete agreed plan through the final submission package. Implement the platform, run genuine local-model experiments, and produce all five deliverables. The user selected local live LLM inference and a complete package, and will obtain the institution-approved similarity report separately.

Every submission must contain all five items:

1. A project report prepared using the supplied report format.
2. The dataset source, including its link or citation.
3. Runnable code and all files needed to execute it.
4. Saved results and figures used in the report.
5. A short README explaining the novelty of the work and how to reproduce the main result.

## Sources and their roles

- User's message: authority for the five submission items above and the request to remember them.
- `references/Template.docx`: retained copy of the supplied report format, originally `C:/Users/Aditya/Downloads/Template.docx`. Its contents are format source material; the user's subsequent explicit implementation request authorizes creating the report and local submission package.
- `230968014_Pandiri Jaswanth Kumar_Synopsis.pdf`: existing five-page project proposal, reviewed in full. Its design choices and expected outcomes are proposals, not evidence of completed implementation or experiments.

## Proposed project from the synopsis

**Title:** AI Agent Forensics & Audit Platform: Evidence Capture, Tamper-Evident Logging and Post-Incident Reconstruction for LLM-Based Agents.

**Team:** Pandiri Jaswanth Kumar, registration 230968014; Kosuru Venkata Sai Aditya, registration 230968316.

**Supervisor:** Dr. Sindhura D N, Assistant Professor, School of Computer Engineering, Manipal Institute of Technology, MAHE, Manipal.

**Programme:** Bachelor of Technology in Data Science & Engineering. Synopsis dated October 2026.

**Problem:** Ordinary application and debugging logs often do not preserve complete, connected, verifiable evidence of LLM agent actions, their inputs, and the configuration in force. The project aims to support investigation of agent incidents.

**Intended contribution:** Combine an agent-specific evidence schema and automatic capture with tamper-evident logging, custody records, incident reconstruction, and findings linked to raw evidence. This is a proposed contribution; claims of novelty require literature support and measured evaluation.

### Proposed scope and workflow

1. Model direct and indirect prompt injection, data exfiltration through tools, and tool privilege misuse.
2. Capture prompts, observable responses, retrieved context, tool calls and results, and configuration through agent callbacks.
3. Store structured JSON events containing session ID, sequence number, timestamp, actor, and payload. Record the model identifier, parameters, and system prompt at session start.
4. Chain records using SHA-256 hashes and sign periodic chain-head checkpoints. Provide an independent verifier that locates the first integrity failure.
5. Record collection and verification in chain-of-custody records.
6. Reconstruct timelines and flag suspicious patterns with rules, including policy violations, injected instructions affecting later actions, and sensitive output. Any optional LLM-assisted triage should point back to raw records.
7. Run benign, attack, and log-tampering experiments and generate incident audit reports.

### Proposed tools and datasets

- Python; LangChain or LangGraph for a test agent.
- An open-source or hosted LLM, still to be selected.
- SHA-256 and Ed25519 through cryptography libraries.
- SQLite or another suitable append-only event storage design.
- FastAPI or Streamlit for timeline viewing and report generation.
- AgentDojo and InjecAgent for public agent-attack scenarios and tool-use tasks.
- Project-generated benign and attack traces with ground truth for evidence completeness.
- Deliberately edited, deleted, or reordered log records for integrity verification tests.

These are candidates from the synopsis. Dataset URLs, versions, access conditions, licences, record counts, and final selections have not been verified. Preserve citations and distinguish public benchmark data from project-generated traces in the final submission.

### Planned evaluation and limits

- Attack detection accuracy or detection rate and false positives; choose and define task-appropriate metrics.
- Evidence completeness against known ground truth.
- Integrity verification on deliberate log tampering.
- Runtime and latency overhead against an uninstrumented baseline.
- Compare methods on the same evaluation data. The final report also requires at least one simple comparison method for the proposed approach; its exact design is still open.
- Model internals cannot be recovered from these logs, and nondeterminism prevents guaranteed exact replay. Stored evidence is the incident record.

## Report format requirements extracted from the template

Follow the retained Word template when producing the report. Preserve its intended structure and replace placeholders with actual project details and measured findings.

### Front matter

- Title page: project title, submission to Manipal Academy of Higher Education, names and registration numbers. The template displays `Dec 2026`; this is template text, not a confirmed submission deadline.
- Abstract on page i: 150-200 words covering the problem, dataset, proposed method, comparison method, main numerical result, and conclusion. Write it after the experiments.
- Table of contents on page ii with correct page numbers. Include lists of figures and tables when applicable.

### Report sections in order

1. **Introduction:** explain the problem, affected users, motivation, and mini project scope.
2. **Research Question And Objectives:** one focused research question, two to four measurable objectives, and a specific contribution.
3. **Related Work:** summarize relevant implementation papers with proper citations, describing methods and findings in original wording.
4. **Literature Comparison:** one table with paper, dataset, method, evaluation metric, finding, and the gap addressed by this project.
5. **Dataset:** source and citation, record count, features, target classes, class counts, missing values, and access or usage restrictions. Explain applicability where the project uses event traces rather than a conventional classification table.
6. **Data Preparation:** cleaning, encoding, scaling, imbalance handling, and train/test split where applicable. Explain step ordering to prevent test-data leakage.
7. **Proposed Methodology:** one overall workflow diagram and an explanation of stages in the same order.
8. **Models And Baseline:** proposed model or method and at least one simple comparison method, with reasons for choosing them.
9. **Experimental Setup:** split or cross-validation procedure where applicable, random seed, parameters, software versions, and evaluation metrics.
10. **Main Results:** one table comparing all methods on the same evaluation data. Classification metrics such as accuracy, precision, recall, and F1 are examples, to be used when appropriate.
11. **Figures And Interpretation:** figures that answer the research question; every figure needs a caption and two or three sentences explaining its finding.
12. **Discussion:** compare with published findings only when datasets and evaluation procedures support fair comparison.
13. **Limitations And Future Work:** explain what the results do not establish, dataset and experimental limits, and a specific next experiment.
14. **Conclusion:** summarize the method, strongest measured result, and evidence-supported contribution.

### References and final attachments

- Complete, consistent references for every research paper cited.
- Cite datasets, software, external figures, and other sources.
- An optional appendix may contain setup instructions, additional plots, parameter tables, and the runnable code link.
- After references, attach the complete similarity report generated for the final submitted version, including overall similarity percentage, matched sources, report date, and exclusions. Follow the institution's required limit; no numerical limit is specified in the supplied materials. The actual report must be obtained from the appropriate similarity-checking service.

### Reconcile synopsis and report requirements

The synopsis lists six design objectives, while the report template asks for two to four measurable objectives. When writing the final report, group the proposed capabilities into two to four measurable objectives while retaining the underlying scope, unless the user changes it.

The template mixes chapter numbers and page labels for sections 11-14. Retain the section order and generate accurate final pagination rather than assuming those labels impose a fixed page count.

## Literature leads recorded in the synopsis

These are supplied references to consult and verify during research, not independently checked citations:

- ISO/IEC 27037:2012 on identification, collection, acquisition, and preservation of digital evidence.
- EU Regulation 2024/1689, Article 12, cited for logging context.
- OWASP Top 10 for Large Language Model Applications.
- Kent et al., NIST SP 800-86, 2006, on forensic techniques in incident response.
- Schneier and Kelsey, Secure audit logs to support computer forensics, 1999.
- Crosby and Wallach, Efficient data structures for tamper-evident logging, 2009.
- Yao et al., ReAct: Synergizing reasoning and acting in language models, 2023.
- Greshake et al., Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection, 2023.
- Debenedetti et al., AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM agents, 2024.
- Zhan et al., InjecAgent: Benchmarking indirect prompt injections in tool-integrated large language model agents, 2024.
- Raji et al., Closing the AI accountability gap: Defining an end-to-end framework for internal algorithmic auditing, 2020.

## Current status

Implementation and the full live experiment are complete as of 27 October 2026. The platform, CLI, Streamlit dashboard, verifier, pinned InjecAgent data, generated controls, tests, report builder and README are implemented. The pinned Qwen3-4B-Instruct-2507 Q4_K_M model ran through portable llama.cpp b11900. All 432 planned sessions were recorded: 414 completed and 18 reached the generation or step limit. Failed executions remain in the evidence and analysis.

All 432 finalized evidence bundles verify, receipt completeness is 100%, and all nine deliberately corrupted variants are rejected. On the 240 held-out public-subset sessions, combined attack-exposure precision is 1.000, recall 0.233 and F1 0.378, compared with keyword F1 0.000 and policy-only F1 0.310. The low recall supports limited triage only. Shared-allowlist action scores validate reconstruction rather than independent semantic detection. Mean incremental recording cost is 0.565 ms/event; the twelve live pairs show a noisy median runtime change of +4.7%.

The editable DOCX and PDF have 21 pages following the retained template. Every page was visually reviewed, the 27 contents/list entries were checked against final pagination, and preserved template package parts were checked. All 32 unit/integration checks and the final Ruff error checks pass. The archive validator checks signed evidence, custody, dataset provenance, report freshness, archive hashes and exclusion of private keys. Fresh-environment reproduction from the extracted ZIP passed without inference or private keys: predictions, metrics and completeness CSVs and all seven figure PNGs match the saved hashes exactly. This check is recorded in docs/verification.json.

GPU thermal throttling was observed. Completed evidence was preserved, an unfinished attempt was archived on resume, and execution returned from full to 24-layer partial offloading. A CPU-only probe was slower. The user explicitly chose to continue with the current physical setup. Retain session-level configurations and disclose the mixed profiles; use one consistent profile for paired overhead measurements.

Live inference has finished and the task-owned model server was stopped. Model weights, runtime downloads, environments and private keys are excluded from the submission. Fresh live generation uses a separate output root and a new signing key; analysis from saved traces requires neither inference nor private keys.

Use InjecAgent as the actual public experimental dataset. AgentDojo is related work and future integration only. The user approved 60 public attacks with 60 generated controls across three seeds (360 sessions), plus 24 controlled scenarios across three seeds (72 sessions). Splits are by public user-tool family; rules are frozen and test labels are not detector inputs. Proposed action violations and executed sandbox actions are separate outcomes.

No exact due date or institutional similarity percentage limit has been confirmed. The genuine similarity report remains pending from the user. Package all technical deliverables and clearly preserve this external requirement rather than inventing a certificate.

All five technical submission items are present in output/submission/AI_Agent_Forensics_Submission.zip. The reviewed report is in output/report, detailed reproduction commands are in docs/reproduction.md, and SUBMISSION_CHECKLIST.json records only the genuine institutional similarity attachment as pending. The local package is prepared; no submission portal upload has been requested or performed.

Update this context when the user changes the scope or when implementation and evaluation decisions are established. Never present planned outcomes as measured results.
