/*

  SQLwrite
 
  by Emery Berger <https://emeryberger.com>

  Translates natural-language queries to SQL.
  
*/

#if !defined(INCLUDE_RANDOM_SAMPLES)
#define INCLUDE_RANDOM_SAMPLES 1
#endif
#if !defined(INCLUDE_INDEXES)
#define INCLUDE_INDEXES 1
#endif
#if !defined(TRANSLATE_QUERY_BACK_TO_NL)
// #define TRANSLATE_QUERY_BACK_TO_NL 0 // for experiments only
#define TRANSLATE_QUERY_BACK_TO_NL 1
#endif
#if !defined(RETRY_ON_EMPTY_RESULTS)
#define RETRY_ON_EMPTY_RESULTS 1
#endif
#if !defined(RETRY_ON_TOO_MANY_RESULTS)
#define RETRY_ON_TOO_MANY_RESULTS 0
#endif
#if !defined(MAX_RETRIES_ON_RESULTS)
#define MAX_RETRIES_ON_RESULTS 5
#endif
#if !defined(MAX_RETRIES_VALIDITY)
#define MAX_RETRIES_VALIDITY 5
#endif
#if !defined(NUM_CANDIDATES)
#define NUM_CANDIDATES 3
#endif
#if !defined(MAX_OUTPUT_LINES)
#define MAX_OUTPUT_LINES 5
#endif

#define LARGE_QUERY_THRESHOLD 10

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include <string>
#include <vector>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <fmt/core.h>
#include <fmt/format.h>

#ifdef SQLWRITE_AUTOLOAD
// Built-in mode - use regular SQLite API
#include <sqlite3.h>
#else
// Extension mode - use extension API
#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1;
#endif

#include "llm_backend.hpp"
#include "aistream.hpp"

std::string prompt("[SQLwrite] ");

const bool DEBUG = false;

#include <iostream>
#include <sstream>

std::string prefaceWithPrompt(const std::string& inputString, const std::string& prompt) {
    std::stringstream input(inputString);
    std::stringstream output;
    std::string line;

    while (std::getline(input, line)) {
      output << prompt << line << '\n';
    }

    return output.str();
}

/* 
    std::string originalString = "Hello\nWorld\nThis is a test";
    std::string prompt = "> ";

    std::string newString = prefaceWithPrompt(originalString, prompt);

    std::cout << newString;
*/


// Function to calculate SHA256 hash of a string
std::string calculateSHA256Hash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
#else
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
#endif

    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(mdctx, hash, nullptr);


#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_destroy(mdctx);
#else
    EVP_MD_CTX_free(mdctx);
#endif

    std::string hashString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hashString += fmt::format("{:02x}", hash[i]);
    }

    return hashString;
}

// SQLite callback function to retrieve query results
int callback(void* data, int argc, char** argv, char** /* azColName */) {
    std::list<std::string>& resultList = *static_cast<std::list<std::string>*>(data);

    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            resultList.push_back(argv[i]);
        }
    }

    return 0;
}

int lines_printed = 0;

int print_em(void* data, int c_num, char** c_vals, char** c_names) {
    for (int i = 0; i < c_num; i++) {
      std::cout << (c_vals[i] ? c_vals[i] : "");
      if ((i < c_num-1) && (c_num > 1)) {
	std::cout << "|";
      }
    }
    std::cout << std::endl;
    return 0;
}

std::string query_result;

int count_em(void* data, int c_num, char** c_vals, char** c_names) {
  for (int i = 0; i < c_num; i++) {
    query_result += (c_vals[i] ? c_vals[i] : "");
    if ((i < c_num - 1) && (c_num > 1)) {
      query_result += "|";
    }
  }
  query_result += "\n";
  lines_printed++;
  return 0;
}

struct truncated_print_data {
  int lines_printed = 0;
  int total_rows = 0;
  int max_lines = MAX_OUTPUT_LINES;
  std::string accumulated_output;
};

int truncated_print_em(void* data, int c_num, char** c_vals, char** c_names) {
  auto* tpd = static_cast<truncated_print_data*>(data);
  tpd->total_rows++;

  std::string row;
  for (int i = 0; i < c_num; i++) {
    row += (c_vals[i] ? c_vals[i] : "");
    if ((i < c_num - 1) && (c_num > 1)) {
      row += "|";
    }
  }

  if (tpd->lines_printed < tpd->max_lines) {
    tpd->accumulated_output += row + "\n";
    tpd->lines_printed++;
  }

  return 0;
}

#include <iostream>
#include <string>

std::string removeEscapedCharacters(const std::string& s) {
    std::string result = s;
    std::size_t pos = result.find("\\");
    while (pos != std::string::npos) {
        if (result[pos+1] == 'n') { // Check if escaped newline
            result.replace(pos, 2, " "); // Replace with single space
        } else if (result[pos+1] == '"') { // Check if escaped quote
            result.erase(pos, 1); // Remove backslash
        }
        pos = result.find("\\", pos+1); // Find next escaped character
    }
    return result;
}


std::string removeEscapedNewlines(const std::string& s) {
    std::string result = s;
    std::size_t pos = result.find("\\n");
    while (pos != std::string::npos) {
      result.replace(pos, 2, " ");
        pos = result.find("\\n", pos);
    }
    return result;
}


nlohmann::json sampleSQLiteDistinct(sqlite3* DB, int N) {
    nlohmann::json result;

    // Query for all tables in the database
    std::string tables_query = "SELECT name FROM sqlite_master WHERE type='table';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(DB, tables_query.c_str(), -1, &stmt, 0);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string table_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        // Query for column names in current table
        std::string columns_query = fmt::format("PRAGMA table_info({});", table_name);
        sqlite3_stmt* column_stmt;
        sqlite3_prepare_v2(DB, columns_query.c_str(), -1, &column_stmt, 0);

        while (sqlite3_step(column_stmt) == SQLITE_ROW) {
            std::string column_name = reinterpret_cast<const char*>(sqlite3_column_text(column_stmt, 1));

	    // Only sample from text types.
	    auto column_type = sqlite3_column_type(column_stmt, 1);
	    if (column_type != SQLITE_TEXT) {
	      continue;
	    }
	    
            // Query for N random distinct values from current column
            std::string values_query = fmt::format("SELECT DISTINCT {} FROM {} ORDER BY RANDOM() LIMIT {};", column_name, table_name, N);
            sqlite3_stmt* values_stmt;
            sqlite3_prepare_v2(DB, values_query.c_str(), -1, &values_stmt, 0);

	    std::vector<std::string> column_values;
	    while (sqlite3_step(values_stmt) == SQLITE_ROW) {
	      const char* data = reinterpret_cast<const char*>(sqlite3_column_text(values_stmt, 0));
	      if (data != nullptr) {
		// Only include non-null, non-numeric data.
		// To decide if something is numeric, we try to convert it to an int or a float; if this succeeds, we skip it.
		// We also limit the size of any text fields we include.
		try {
		  auto f = std::stof(data);
		} catch (...) {
		  try {
		    auto i = std::stoi(data);
		  } catch (...) {
		    // Now, only include text fields below a certain length. This is a magic number.
		    std::string truncated_data(data, std::min<size_t>(10, std::strlen(data)));
		    if (DEBUG) {
		      std::cerr << "NON NUMERIC: " << truncated_data << std::endl;
		    }
		    column_values.push_back(truncated_data.c_str());
		  }
		}
	      }
	    }

	    if (column_values.size() > 1) {
	      result[table_name][column_name] = column_values;
	    }
            sqlite3_finalize(values_stmt);
        }
        sqlite3_finalize(column_stmt);
    }
    sqlite3_finalize(stmt);

    return result;
}


// Function to rephrase a query using ChatGPT
std::list<std::string> rephraseQuery(ai::aistream& ai, const std::string& query, int n = 10)
{
  // Query the ChatGPT model for rephrasing
  auto promptq = fmt::format("Rephrase the following query {} times, all using different wording. Produce a JSON object with the result as a list with the field \"Rewording\". Do not include any SQL in any rewording. Query to rephrase: '{}'", n, query);

  ai.reset();
  ai << json({
      { "role", "assistant" },
	{ "content", "You are an assistant who is an expert in rewording natural language expressions. You ONLY respond with JSON objects." }
    });
  ai << json({
      {"role", "user" },
	{"content", promptq.c_str() }
    });
  ai << ai::validator([](const json& j) {
    // Enforce list output
    volatile auto list = j["Rewording"].get<std::list<std::string>>();
    return true;
  });

  json json_response;
  ai >> json_response;
  
  // Parse the response and extract the rephrased queries
  auto rephrasedQueries = json_response["Rewording"].get<std::list<std::string>>();
  return rephrasedQueries;
}

static bool translateCandidates(ai::aistream& ai,
			   sqlite3_context *ctx,
			   int argc,
			   const char * query,
			   json& json_response,
			   std::vector<std::string>& sql_candidates)
{

  /* ---- build a query prompt to translate from natural language to SQL. ---- */
  // The prompt consists of all table names and schemas, plus any indexes, along with directions.

  // Print all loaded database schemas
  sqlite3 *db = sqlite3_context_db_handle(ctx);
  sqlite3_stmt *stmt;

  auto nl_to_sql = fmt::format(
    "Given a database with the following tables, schemas, indexes, and samples "
    "for each column, write {} plausible SQL queries in SQLite's SQL dialect that "
    "answer this question or produce the desired report: '{}'. "
    "Each candidate should represent a different reasonable interpretation of the query. "
    "Produce a JSON object with a field \"Candidates\" containing an array of objects, "
    "each having a \"SQL\" field with the query and an \"Explanation\" field briefly "
    "describing the interpretation. "
    "Also include a field \"Indexing\" with a list of suggestions as SQL commands to "
    "create indexes that would improve query performance. Do so only if those indexes "
    "are not already given in 'Existing indexes'. "
    "The produced queries must only reference columns listed in the schemas. "
    "Refer to the samples to form the queries, taking into account format and "
    "capitalization. Only produce output that can be parsed as JSON.\n",
    NUM_CANDIDATES, query);

  sqlite3_prepare_v2(db, "SELECT name, sql FROM sqlite_master WHERE type='table' OR type='view'", -1, &stmt, NULL);

  auto total_tables = 0;

  // Print the schema for each table.
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    const char *sql = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    // Strip any quote characters.
    std::string sql_str(sql);
    sql_str.erase(std::remove(sql_str.begin(), sql_str.end(), '\''), sql_str.end());
    sql_str.erase(std::remove(sql_str.begin(), sql_str.end(), '\"'), sql_str.end());
    sql_str.erase(std::remove(sql_str.begin(), sql_str.end(), '`'), sql_str.end());
    nl_to_sql += fmt::format("Schema for {}: {}\n", name, sql_str.c_str());
    total_tables++;
  }
  sqlite3_finalize(stmt);

  // Fail gracefully if no databases are present.
  if (total_tables == 0) {
    std::cout << prompt.c_str() << "you need to load a table first." << std::endl;
    return false;
  }

  // Add indexes, if any.
#if INCLUDE_INDEXES
  auto printed_index_header = false;
  sqlite3_prepare_v2(db, "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type='index'", -1, &stmt, NULL);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    try {
      const char *tbl_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
      const char *sql = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
      if (!printed_index_header && tbl_name && sql) {
	nl_to_sql += "\n\nExisting indexes:\n";
	printed_index_header = true;
      }
      nl_to_sql += fmt::format("Index for {}: {}\n", tbl_name, sql);
    } catch (fmt::v9::format_error& fe) {
      // Ignore indices where the query response is null, which could get us here.
    }
  }
  sqlite3_finalize(stmt);
#endif

  // Randomly sample values from the database.
#if INCLUDE_RANDOM_SAMPLES
  auto sample_value_json = sampleSQLiteDistinct(db, 5); // magic number FIXME
  nl_to_sql += fmt::format("\nSample values for columns: {}\n", sample_value_json.dump(-1, ' ', false, json::error_handler_t::replace));
#endif

  /* ----  translate the natural language query to SQL and execute it (and request indexes) ---- */

  ai << json({
      { "role", "assistant" },
	{ "content", "You are a programming assistant who is an expert in generating SQL queries from natural language. You ONLY respond with JSON objects." }
    });

  ai << json({
      { "role", "user" },
	{ "content", nl_to_sql.c_str() }
    });

  ai << ai::validator([&](const json& j) {
    try {
      // Ensure we got a Candidates array.
      auto& candidates = j["Candidates"];
      if (!candidates.is_array() || candidates.empty()) {
        return false;
      }

      sql_candidates.clear();
      for (auto& candidate : candidates) {
        std::string sql = candidate["SQL"].get<std::string>();
        // Verify explanation exists.
        volatile auto explanation_test = candidate["Explanation"].get<std::string>();

        // Clean up the SQL.
        sql = removeEscapedNewlines(sql);
        sql = removeEscapedCharacters(sql);

        // Validate SQL by executing it.
        auto rc = sqlite3_exec(db, sql.c_str(),
            [](void*, int, char**, char**) { return 0; },
            nullptr, nullptr);
        if (rc != SQLITE_OK) {
          if (DEBUG) {
            std::cerr << fmt::format("{}Error executing candidate SQL \"{}\": {}\n",
                prompt.c_str(), sql.c_str(), sqlite3_errmsg(db));
          }
          throw ai::exception(ai::exception_value::OTHER,
              fmt::format("One of the candidate queries (\"{}\") caused SQLite to fail "
                  "with this error: {}. Please regenerate all candidates with valid SQL.",
                  sql, std::string(sqlite3_errmsg(db))));
        }
        sql_candidates.push_back(sql);
      }

      // Validate Indexing field.
      for (auto& item : j["Indexing"]) {
        volatile auto item_test = item.get<std::string>();
      }
    } catch (ai::exception&) {
      throw;
    } catch (std::exception& e) {
      return false;
    }
    return true;
  });

  json json_result;
  try {
    ai >> json_result;
  } catch (...) {
    json_result = json({ {"Candidates", json::array()}, {"Indexing", json::array()} });
    return false;
  }
  json_response = json_result;

  return !sql_candidates.empty();
}

static void real_ask_command(sqlite3_context *ctx, int argc, const char * query) { //  sqlite3_value **argv) {

  sqlite3 *db = sqlite3_context_db_handle(ctx);
  json json_result;
  std::string query_str (query);
  std::vector<std::string> sql_candidates;

  ai::aistream::params ai_params;
  ai_params.maxRetries = MAX_RETRIES_VALIDITY;
  ai_params.debug = DEBUG;
  ai::aistream ai (ai_params);

  ai << ai::config::GPT_4_0;

  bool r = translateCandidates(ai, ctx, argc, query_str.c_str(), json_result, sql_candidates);
  if (!r || sql_candidates.empty()) {
    std::cerr << prompt.c_str() << "Unfortunately, we were not able to successfully translate that query." << std::endl;
    return;
  }

  // Display each candidate with truncated output.
  auto& candidates_json = json_result["Candidates"];
  for (size_t i = 0; i < sql_candidates.size(); i++) {
    const auto& sql = sql_candidates[i];

    // Get explanation if available.
    std::string explanation;
    if (i < candidates_json.size() && candidates_json[i].contains("Explanation")) {
      explanation = candidates_json[i]["Explanation"].get<std::string>();
    }

    // Print candidate header.
    std::cerr << fmt::format("\n{}--- Candidate {} of {} ---\n",
        prompt.c_str(), i + 1, sql_candidates.size());

    // Print the SQL.
    std::cerr << fmt::format("{}SQL: {}\n", prompt.c_str(), sql.c_str());

    // Print explanation if available.
    if (!explanation.empty()) {
      std::cerr << fmt::format("{}Interpretation: {}\n", prompt.c_str(), explanation.c_str());
    }

    // Execute with truncated output.
    truncated_print_data tpd;
    tpd.max_lines = MAX_OUTPUT_LINES;
    auto rc = sqlite3_exec(db, sql.c_str(), truncated_print_em, &tpd, nullptr);

    if (rc != SQLITE_OK) {
      std::cerr << fmt::format("{}Error executing query: {}\n",
          prompt.c_str(), sqlite3_errmsg(db));
      continue;
    }

    // Print the accumulated (truncated) output.
    if (tpd.lines_printed > 0) {
      std::cout << tpd.accumulated_output;
    }

    // Show truncation indicator or empty result notice.
    if (tpd.total_rows > tpd.max_lines) {
      std::cerr << fmt::format("{}... ({} more rows, {} total)\n",
          prompt.c_str(), tpd.total_rows - tpd.max_lines, tpd.total_rows);
    } else if (tpd.total_rows == 0) {
      std::cerr << fmt::format("{}(no results)\n", prompt.c_str());
    }
  }

  // Indexing suggestions (aggregate, once for all candidates).
  if (json_result.contains("Indexing") && json_result["Indexing"].size() > 0) {
    std::cout << "\n" << prompt.c_str() << "indexing suggestions to improve performance:" << std::endl;
    int idx = 0;
    for (auto& item : json_result["Indexing"]) {
      idx++;
      std::cout << fmt::format("({}): {}\n", idx, item.get<std::string>());
    }
  }

  /* ----  translate the first candidate SQL back to natural language ---- */
#if TRANSLATE_QUERY_BACK_TO_NL
  if (!sql_candidates.empty()) {
    ai.reset();
    ai << json({
        { "role", "assistant" },
        { "content", "You are a programming assistant who is an expert in translating SQL queries to natural language. You ONLY respond with JSON objects." }
      });

    auto translate_to_natural_language_query = fmt::format("Given the following SQL query, convert it into natural language: '{}'. Produce a JSON object with the translation as a field \"Translation\". Only produce output that can be parsed as JSON.\n", sql_candidates[0]);
    ai << json({
        { "role", "user" },
        { "content", translate_to_natural_language_query.c_str() }
      });
    std::string translation;
    ai << ai::validator([&](const json& j){
      try {
        translation = j["Translation"].get<std::string>();
        return true;
      } catch (std::exception& e) {
        return false;
      }
    });
    json translate_result;
    ai >> translate_result;
    std::cout << fmt::format("\n{}translation of candidate 1 to natural language:\n{}", prompt.c_str(), prefaceWithPrompt(translation, prompt).c_str());
  }
#endif
}
     
static void ask_command(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  if (argc != 1) {
    sqlite3_result_error(ctx, "The 'ask' command takes exactly one argument.", -1);
  }
  auto query = (const char *) sqlite3_value_text(argv[0]);
  real_ask_command(ctx, argc, query); // argv);
}


static void sqlwrite_command(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  if (argc != 1) {
    sqlite3_result_error(ctx, "The 'sqlwrite' command takes exactly one argument.", -1);
  }
  auto query = (const char *) sqlite3_value_text(argv[0]);
  real_ask_command(ctx, argc, query);
}


extern "C" int sqlite3_sqlwrite_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi)
{
  openai::start();
  
#ifndef SQLWRITE_AUTOLOAD
  // Only use extension API when loaded dynamically
  SQLITE_EXTENSION_INIT2(pApi);
#endif
    
  int rc;

  rc = sqlite3_create_function(db, "ask", -1, SQLITE_UTF8, db, &ask_command, NULL, NULL);
  if (rc != SQLITE_OK) {
    if (pzErrMsg) *pzErrMsg = sqlite3_mprintf("Failed to create ask function: %s", sqlite3_errmsg(db));
    return rc;
  }
  rc = sqlite3_create_function(db, "sqlwrite", -1, SQLITE_UTF8, db, &sqlwrite_command, NULL, NULL);
  if (rc != SQLITE_OK) {
    if (pzErrMsg) *pzErrMsg = sqlite3_mprintf("Failed to create sqlwrite function: %s", sqlite3_errmsg(db));
    return rc;
  }
  
  // Check for credentials using the backend detection
  auto backend = llm::create_backend();
  if (!backend) {
    printf("To use SQLwrite, you need API credentials:\n");
    printf("  Option 1 (OpenAI): export OPENAI_API_KEY=sk-...\n");
    printf("  Option 2 (AWS Bedrock): export AWS_ACCESS_KEY_ID=... or ~/.aws/credentials\n");
    if (pzErrMsg) *pzErrMsg = sqlite3_mprintf("No API credentials found.\n");
    return SQLITE_ERROR;
  }
  
  const char* provider = (llm::detect_provider() == llm::Provider::BEDROCK) ? "AWS Bedrock (Claude)" : "OpenAI";
  printf("SQLwrite extension initialized with %s.\n", provider);
  printf("Use natural language queries like: select ask('show me all artists.');\n");

  return SQLITE_OK;
}
