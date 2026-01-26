#ifndef LLM_BACKEND_HPP_
#define LLM_BACKEND_HPP_

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <cctype>

#ifndef CURL_STATICLIB
#include <curl/curl.h>
#else
#include "curl/curl.h"
#endif

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "json.hpp"

namespace llm {

using json = nlohmann::json;

enum class Provider {
    OPENAI,
    BEDROCK
};

struct Message {
    std::string role;
    std::string content;
};

struct Response {
    bool success = false;
    std::string content;
    std::string error;
    unsigned int completion_tokens = 0;
    unsigned int prompt_tokens = 0;
    unsigned int total_tokens = 0;
};

// Abstract backend interface
class Backend {
public:
    virtual ~Backend() = default;
    virtual Response chat(const std::vector<Message>& messages, const std::string& model) = 0;
};

namespace detail {

inline size_t write_callback(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

inline std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

inline std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);

    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

inline std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(), key.c_str(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
         hash, &len);

    return std::string(reinterpret_cast<char*>(hash), len);
}

inline std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(), key.c_str(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
         hash, &len);

    std::ostringstream ss;
    for (unsigned int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

inline std::string url_encode(const std::string& str) {
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex;

    for (char c : str) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << '%' << std::setw(2) << std::uppercase << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return encoded.str();
}

inline std::string get_utc_timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm* gmt = std::gmtime(&now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", gmt);
    return std::string(buf);
}

inline std::string get_utc_date() {
    std::time_t now = std::time(nullptr);
    std::tm* gmt = std::gmtime(&now);
    char buf[16];
    std::strftime(buf, sizeof(buf), "%Y%m%d", gmt);
    return std::string(buf);
}

// Strip markdown code blocks from LLM responses
inline std::string strip_markdown_json(const std::string& content) {
    std::string result = content;

    // Remove leading ```json or ```
    size_t start = result.find("```");
    if (start != std::string::npos) {
        size_t newline = result.find('\n', start);
        if (newline != std::string::npos) {
            result = result.substr(newline + 1);
        }
    }

    // Remove trailing ```
    size_t end = result.rfind("```");
    if (end != std::string::npos) {
        result = result.substr(0, end);
    }

    return trim(result);
}

} // namespace detail

// OpenAI Backend
class OpenAIBackend : public Backend {
public:
    explicit OpenAIBackend(const std::string& api_key) : api_key_(api_key) {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~OpenAIBackend() override {
        curl_global_cleanup();
    }

    Response chat(const std::vector<Message>& messages, const std::string& model) override {
        Response resp;

        json msgs_json = json::array();
        for (const auto& msg : messages) {
            msgs_json.push_back({{"role", msg.role}, {"content", msg.content}});
        }

        json request_body = {
            {"model", model},
            {"messages", msgs_json}
        };

        std::string body = request_body.dump();

        CURL* curl = curl_easy_init();
        if (!curl) {
            resp.error = "Failed to initialize curl";
            return resp;
        }

        std::string response_str;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Authorization: Bearer " + api_key_).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, "https://api.openai.com/v1/chat/completions");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, detail::write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_str);

        CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            resp.error = "curl error: " + std::string(curl_easy_strerror(res));
            std::cerr << "[LLM Backend] " << resp.error << std::endl;
            return resp;
        }

        try {
            json response_json = json::parse(response_str);

            if (response_json.contains("error")) {
                resp.error = response_json["error"]["message"].get<std::string>();
                std::cerr << "[LLM Backend] API error: " << resp.error << std::endl;
                return resp;
            }

            std::string raw_content = response_json["choices"][0]["message"]["content"].get<std::string>();
            resp.content = detail::strip_markdown_json(raw_content);

            if (response_json.contains("usage")) {
                resp.completion_tokens = response_json["usage"]["completion_tokens"].get<unsigned int>();
                resp.prompt_tokens = response_json["usage"]["prompt_tokens"].get<unsigned int>();
                resp.total_tokens = response_json["usage"]["total_tokens"].get<unsigned int>();
            }

            resp.success = true;
        } catch (const std::exception& e) {
            resp.error = "JSON parse error: " + std::string(e.what());
            std::cerr << "[LLM Backend] " << resp.error << std::endl;
            std::cerr << "[LLM Backend] Response was: " << response_str << std::endl;
        }

        return resp;
    }

private:
    std::string api_key_;
};

// AWS Bedrock Backend
class BedrockBackend : public Backend {
public:
    BedrockBackend(const std::string& access_key, const std::string& secret_key,
                   const std::string& session_token, const std::string& region)
        : access_key_(access_key), secret_key_(secret_key),
          session_token_(session_token), region_(region) {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~BedrockBackend() override {
        curl_global_cleanup();
    }

    Response chat(const std::vector<Message>& messages, const std::string& model) override {
        Response resp;

        // Convert messages to Claude format
        // Claude requires: first message must be "user", roles must alternate
        // "assistant" messages before any "user" are treated as system content

        std::string system_content;
        json claude_messages = json::array();
        std::string last_role;

        for (const auto& msg : messages) {
            if (msg.role == "assistant" && claude_messages.empty()) {
                // Treat early "assistant" messages as system content
                if (!system_content.empty()) system_content += "\n";
                system_content += msg.content;
            } else if (msg.role == "user" || msg.role == "assistant") {
                // Merge consecutive same-role messages
                if (msg.role == last_role && !claude_messages.empty()) {
                    std::string prev_content = claude_messages.back()["content"].get<std::string>();
                    claude_messages.back()["content"] = prev_content + "\n" + msg.content;
                } else {
                    claude_messages.push_back({{"role", msg.role}, {"content", msg.content}});
                    last_role = msg.role;
                }
            }
        }

        // Ensure first message is user role (required by Claude)
        if (claude_messages.empty() || claude_messages[0]["role"] != "user") {
            resp.error = "Claude requires first message to be from user role";
            return resp;
        }

        json request_body = {
            {"anthropic_version", "bedrock-2023-05-31"},
            {"max_tokens", 4096},
            {"messages", claude_messages}
        };

        if (!system_content.empty()) {
            request_body["system"] = system_content;
        }

        std::string body = request_body.dump();

        // Build the request path with URL-encoded model ID
        std::string encoded_model = detail::url_encode(model);
        std::string path = "/model/" + encoded_model + "/invoke";
        std::string host = "bedrock-runtime." + region_ + ".amazonaws.com";
        std::string url = "https://" + host + path;

        // Sign the request using AWS SigV4
        std::string timestamp = detail::get_utc_timestamp();
        std::string date = detail::get_utc_date();

        // Create canonical request
        std::string content_hash = detail::sha256_hex(body);

        std::string canonical_headers =
            "content-type:application/json\n"
            "host:" + host + "\n"
            "x-amz-content-sha256:" + content_hash + "\n"
            "x-amz-date:" + timestamp + "\n";

        std::string signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";

        if (!session_token_.empty()) {
            canonical_headers += "x-amz-security-token:" + session_token_ + "\n";
            signed_headers += ";x-amz-security-token";
        }

        std::string canonical_request =
            "POST\n" +
            path + "\n" +
            "\n" +  // empty query string
            canonical_headers + "\n" +
            signed_headers + "\n" +
            content_hash;

        // Create string to sign
        std::string algorithm = "AWS4-HMAC-SHA256";
        std::string credential_scope = date + "/" + region_ + "/bedrock/aws4_request";
        std::string string_to_sign =
            algorithm + "\n" +
            timestamp + "\n" +
            credential_scope + "\n" +
            detail::sha256_hex(canonical_request);

        // Calculate signature
        std::string k_date = detail::hmac_sha256("AWS4" + secret_key_, date);
        std::string k_region = detail::hmac_sha256(k_date, region_);
        std::string k_service = detail::hmac_sha256(k_region, "bedrock");
        std::string k_signing = detail::hmac_sha256(k_service, "aws4_request");
        std::string signature = detail::hmac_sha256_hex(k_signing, string_to_sign);

        // Create authorization header
        std::string authorization = algorithm + " " +
            "Credential=" + access_key_ + "/" + credential_scope + ", " +
            "SignedHeaders=" + signed_headers + ", " +
            "Signature=" + signature;

        // Make the request
        CURL* curl = curl_easy_init();
        if (!curl) {
            resp.error = "Failed to initialize curl";
            return resp;
        }

        std::string response_str;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Host: " + host).c_str());
        headers = curl_slist_append(headers, ("X-Amz-Date: " + timestamp).c_str());
        headers = curl_slist_append(headers, ("X-Amz-Content-Sha256: " + content_hash).c_str());
        headers = curl_slist_append(headers, ("Authorization: " + authorization).c_str());

        if (!session_token_.empty()) {
            headers = curl_slist_append(headers, ("X-Amz-Security-Token: " + session_token_).c_str());
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, detail::write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_str);

        CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            resp.error = "curl error: " + std::string(curl_easy_strerror(res));
            std::cerr << "[LLM Backend] " << resp.error << std::endl;
            return resp;
        }

        try {
            json response_json = json::parse(response_str);

            if (response_json.contains("message")) {
                // Error response from Bedrock
                resp.error = response_json["message"].get<std::string>();
                std::cerr << "[LLM Backend] Bedrock API error: " << resp.error << std::endl;
                return resp;
            }

            // Extract content from Claude's response format
            if (response_json.contains("content") && response_json["content"].is_array() &&
                !response_json["content"].empty()) {
                std::string raw_content = response_json["content"][0]["text"].get<std::string>();
                resp.content = detail::strip_markdown_json(raw_content);
            }

            // Extract token usage
            if (response_json.contains("usage")) {
                if (response_json["usage"].contains("input_tokens")) {
                    resp.prompt_tokens = response_json["usage"]["input_tokens"].get<unsigned int>();
                }
                if (response_json["usage"].contains("output_tokens")) {
                    resp.completion_tokens = response_json["usage"]["output_tokens"].get<unsigned int>();
                }
                resp.total_tokens = resp.prompt_tokens + resp.completion_tokens;
            }

            resp.success = true;
        } catch (const std::exception& e) {
            resp.error = "JSON parse error: " + std::string(e.what()) + " Response: " + response_str;
            std::cerr << "[LLM Backend] " << resp.error << std::endl;
        }

        return resp;
    }

private:
    std::string access_key_;
    std::string secret_key_;
    std::string session_token_;
    std::string region_;
};

// Utility functions

inline bool has_aws_credentials() {
    // Check environment variables first
    const char* access_key = std::getenv("AWS_ACCESS_KEY_ID");
    const char* secret_key = std::getenv("AWS_SECRET_ACCESS_KEY");

    if (access_key && secret_key) {
        return true;
    }

    // Check ~/.aws/credentials file
    const char* home = std::getenv("HOME");
    if (!home) return false;

    std::string creds_path = std::string(home) + "/.aws/credentials";
    std::ifstream creds_file(creds_path);
    if (!creds_file.is_open()) return false;

    std::string line;
    bool has_access = false, has_secret = false;

    while (std::getline(creds_file, line)) {
        if (line.find("aws_access_key_id") != std::string::npos) has_access = true;
        if (line.find("aws_secret_access_key") != std::string::npos) has_secret = true;
    }

    return has_access && has_secret;
}

inline bool has_openai_key() {
    const char* key = std::getenv("OPENAI_API_KEY");
    return key && std::strlen(key) > 0;
}

inline Provider detect_provider() {
    // AWS credentials take priority
    if (has_aws_credentials()) {
        return Provider::BEDROCK;
    }
    return Provider::OPENAI;
}

inline std::string default_model(Provider provider) {
    switch (provider) {
        case Provider::BEDROCK:
            return "anthropic.claude-3-sonnet-20240229-v1:0";
        case Provider::OPENAI:
        default:
            return "gpt-4o";
    }
}

inline std::unique_ptr<Backend> create_backend() {
    // Try AWS Bedrock first
    if (has_aws_credentials()) {
        std::string access_key, secret_key, session_token;
        std::string region = "us-east-1";  // default region

        // Check environment variables first
        const char* env_access = std::getenv("AWS_ACCESS_KEY_ID");
        const char* env_secret = std::getenv("AWS_SECRET_ACCESS_KEY");
        const char* env_session = std::getenv("AWS_SESSION_TOKEN");
        const char* env_region = std::getenv("AWS_REGION");

        if (env_access && env_secret) {
            access_key = env_access;
            secret_key = env_secret;
            if (env_session) session_token = env_session;
            if (env_region) region = env_region;
        } else {
            // Parse ~/.aws/credentials
            const char* home = std::getenv("HOME");
            if (home) {
                std::string creds_path = std::string(home) + "/.aws/credentials";
                std::ifstream creds_file(creds_path);
                std::string line;

                while (std::getline(creds_file, line)) {
                    size_t eq_pos = line.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string key = detail::trim(line.substr(0, eq_pos));
                        std::string value = detail::trim(line.substr(eq_pos + 1));

                        if (key == "aws_access_key_id") access_key = value;
                        else if (key == "aws_secret_access_key") secret_key = value;
                        else if (key == "aws_session_token") session_token = value;
                    }
                }
            }
            if (env_region) region = env_region;
        }

        if (!access_key.empty() && !secret_key.empty()) {
            return std::make_unique<BedrockBackend>(access_key, secret_key, session_token, region);
        }
    }

    // Try OpenAI
    if (has_openai_key()) {
        const char* key = std::getenv("OPENAI_API_KEY");
        return std::make_unique<OpenAIBackend>(key);
    }

    // No credentials found
    return nullptr;
}

} // namespace llm

#endif // LLM_BACKEND_HPP_
