# SQLwrite Development Notes

## Architecture

SQLwrite is a SQLite extension that translates natural language queries to SQL using LLMs.

### Key Components

- `sqlwrite.cpp` - Main extension code, registers `ask()` and `sqlwrite()` SQL functions
- `aistream.hpp` - Stream-based interface for LLM interactions with retry logic
- `llm_backend.hpp` - Abstraction layer supporting multiple LLM providers
- `shell.c` - Modified SQLite shell with auto-load support
- `openai.hpp` - Legacy OpenAI client (kept for reference, no longer used directly)

## Build Modes

### Built-in Mode (sqlwrite-bin)
When compiled with `-DSQLWRITE_AUTOLOAD`:
- Extension is automatically loaded when database opens
- Uses regular SQLite API (`sqlite3.h`)
- No need for `.load` command

### Extension Mode (sqlwrite.so)
When compiled without `SQLWRITE_AUTOLOAD`:
- Loadable extension for any SQLite shell
- Uses extension API (`sqlite3ext.h` + `SQLITE_EXTENSION_INIT1/2`)
- Requires `.load ./sqlwrite` command

### Implementation Details
- `shell.c` modified to call `sqlite3_sqlwrite_init()` in `open_db()` when `SQLWRITE_AUTOLOAD` defined
- `sqlwrite.cpp` conditionally includes `sqlite3.h` vs `sqlite3ext.h` based on build mode
- Both modes built by CMake: `sqlwrite-bin` (built-in) and `sqlwrite.so` (extension)
- Shell binary always uses bundled `shell.c` + `sqlite3.c` to ensure version match

## LLM Backend Integration

### Supported Providers

1. **OpenAI** - Uses GPT-4o via chat completions API
2. **AWS Bedrock** - Uses Claude 3 Sonnet via Bedrock runtime API

### Provider Selection

Priority order:
1. AWS credentials (env vars or `~/.aws/credentials`) → Bedrock
2. `OPENAI_API_KEY` env var → OpenAI

### AWS Bedrock Implementation Notes

#### SigV4 Signing
- URI paths must be URL-encoded in the canonical request (e.g., colons become `%3A`)
- Service name is `bedrock` (not `bedrock-runtime`)
- Host is `bedrock-runtime.{region}.amazonaws.com`

#### Model Selection
- Claude 3 Sonnet (`anthropic.claude-3-sonnet-20240229-v1:0`) supports on-demand throughput
- Newer Claude 4 models require inference profiles - not supported in on-demand mode
- Model ID goes in the URL path: `/model/{model_id}/invoke`

#### Message Format Requirements
Claude has strict message format rules:
- First message MUST be "user" role
- Messages must alternate between "user" and "assistant"
- System prompts go in the `system` field, not as messages

The existing codebase uses "assistant" role for system prompts (OpenAI pattern). The backend handles this by:
- Treating "assistant" messages before any "user" message as system content
- Merging consecutive "user" messages into one
- Properly alternating roles in the final message array

#### Request Format
```json
{
  "anthropic_version": "bedrock-2023-05-31",
  "max_tokens": 4096,
  "system": "...",
  "messages": [{"role": "user", "content": "..."}]
}
```

#### AWS Credentials
- Environment variables take priority: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- Falls back to `~/.aws/credentials` file
- **Important**: `AWS_SESSION_TOKEN` is also read from environment - if set but doesn't match the access key, authentication fails
- When using explicit credentials, run `unset AWS_SESSION_TOKEN` first

## Query Translation Behavior

### Retry Logic
- `RETRY_ON_EMPTY_RESULTS=1` - Retries with fuzzy match hints if query returns no results
- `RETRY_ON_TOO_MANY_RESULTS=0` - **Disabled** - was causing bad translations by telling LLM to constrain queries that legitimately return many results (e.g., "show all artists")

### Random Sampling
- Code samples random rows from database to give LLM context
- Different samples can lead to different interpretations
- This is expected LLM behavior

## Common Issues

1. **"first message must use the user role"** - Claude requires user message first; backend handles this
2. **"roles must alternate"** - Consecutive same-role messages; backend merges them
3. **"on-demand throughput isn't supported"** - Model requires inference profile; use Claude 3 models
4. **Signature mismatch** - Check URI encoding in canonical request
5. **"sqlite3_close() returns 5"** - Unfinalized prepared statements; ensure all `sqlite3_prepare_v2` have matching `sqlite3_finalize`
6. **AWS_SESSION_TOKEN mismatch** - Unset the token when using explicit access key/secret
7. **Bizarre query constraints** - Was caused by `RETRY_ON_TOO_MANY_RESULTS`; now disabled

## Testing

```bash
# Build
cmake -B build && cmake --build build

# Test with Bedrock
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
unset AWS_SESSION_TOKEN
cd build && LD_LIBRARY_PATH=. ./sqlwrite-bin ../test/test.db

# Test query
sqlite> select ask('show me all artists');
```
