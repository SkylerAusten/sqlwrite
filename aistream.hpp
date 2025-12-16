#ifndef AISTREAM_HPP_
#define AISTREAM_HPP_

#include <fmt/format.h>
#include <iostream>
#include <list>
#include <memory>
#include "json.hpp"
#include "llm_backend.hpp"

using json = nlohmann::json;

namespace ai {
  
  enum class config { GPT_3_5, GPT_4_0, CLAUDE_SONNET, CLAUDE_OPUS };
  enum class exception_value { NO_KEY_DEFINED, INVALID_KEY, TOO_MANY_RETRIES, OTHER };

  class stats {
  public:
    unsigned int completion_tokens = 0;
    unsigned int prompt_tokens = 0;
    unsigned int total_tokens = 0;
  };

  class validator {
  public:
    explicit validator(std::function<bool(const json&)> v) : function(v) {}
    std::function<bool(const json&)> function = [](const json&){ return true; };
  };
  
  class exception {
  public:
    explicit exception(exception_value e, const std::string& msg) : _exception(e), _msg(msg) {}
    std::string what() const { return _msg; }
  private:
    exception_value _exception;
    std::string _msg;
  };

  class aistream {
  public:
    struct params {
      std::string apiKey = "";
      std::string keyName = "OPENAI_API_KEY";
      unsigned int maxRetries = 3;
      bool debug = false;
    };
    
    explicit aistream(params p)
      : _maxRetries(p.maxRetries), _debug(p.debug)
    {
      _backend = llm::create_backend();
      if (!_backend) {
        throw ai::exception(ai::exception_value::NO_KEY_DEFINED,
          "No API credentials found. Set OPENAI_API_KEY or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.");
      }
      _provider = llm::detect_provider();
      _model = llm::default_model(_provider);
    }

    aistream& operator<<(const ai::config& config) {
      switch (config) {
      case ai::config::GPT_3_5:
        _model = "gpt-3.5-turbo";
        break;
      case ai::config::GPT_4_0:
        _model = (_provider == llm::Provider::BEDROCK) ? 
          "anthropic.claude-3-sonnet-20240229-v1:0" : "gpt-4o";
        break;
      case ai::config::CLAUDE_SONNET:
        _model = "anthropic.claude-3-sonnet-20240229-v1:0";
        break;
      case ai::config::CLAUDE_OPUS:
        _model = "anthropic.claude-3-opus-20240229-v1:0";
        break;
      }
      return *this;
    }
  
    aistream& operator<<(const validator& v) {
      _validator = v.function;
      return *this;
    }
  
    aistream& operator<<(const json& js) {
      _messages.push_back(js);
      return *this;
    }

    aistream& operator>>(stats& stats) {
      stats = _stats;
      return *this;
    }
      
    aistream& operator>>(json& response_json) {
      response_json = {{}};
      auto retries = _maxRetries;
      
      // Convert messages to backend format
      std::vector<llm::Message> msgs;
      for (const auto& m : _messages) {
        msgs.push_back({m["role"].get<std::string>(), m["content"].get<std::string>()});
      }
      
      while (retries > 0) {
        try {
          if (_debug) {
            std::cerr << "Sending to " << (_provider == llm::Provider::BEDROCK ? "Bedrock" : "OpenAI") 
                      << " model: " << _model << std::endl;
          }
          
          auto resp = _backend->chat(msgs, _model);
          
          if (!resp.success) {
            if (_debug) std::cerr << "API error: " << resp.error << std::endl;
            if (resp.error.find("API key") != std::string::npos || 
                resp.error.find("credentials") != std::string::npos) {
              throw ai::exception(ai::exception_value::INVALID_KEY, resp.error);
            }
            retries--;
            continue;
          }
          
          _result = resp.content;
          if (_debug) std::cerr << "Received: " << _result << std::endl;
          
          _stats.completion_tokens += resp.completion_tokens;
          _stats.prompt_tokens += resp.prompt_tokens;
          _stats.total_tokens += resp.total_tokens;
          
          response_json = json::parse(_result);
          
          if (_validator(response_json)) {
            return *this;
          }
        }
        catch (json::parse_error&) {
          if (_debug) std::cerr << "JSON parse error." << std::endl;
        }
        catch (json::type_error&) {
          if (_debug) std::cerr << "JSON type error." << std::endl;
        }
        catch (ai::exception&) {
          throw;
        }
        catch (std::exception& e) {
          if (_debug) std::cerr << "Error: " << e.what() << std::endl;
        }
        
        retries--;
        if (_debug) std::cerr << "Retrying. Retries remaining: " << retries << std::endl;
      }
      
      throw ai::exception(ai::exception_value::TOO_MANY_RETRIES,
        fmt::format("Maximum number of retries exceeded ({}).", _maxRetries));
    }

    void reset() {
      _result = "";
      _messages.clear();
      _validator = [](const json&) { return true; };
    }
  
  private:
    std::unique_ptr<llm::Backend> _backend;
    llm::Provider _provider;
    std::string _model;
    std::list<json> _messages;
    std::string _result;
    const unsigned int _maxRetries;
    const bool _debug;
    stats _stats;
    std::function<bool(const json&)> _validator = [](const json&){ return true; };
  };

}

// Keep openai::start() for backward compatibility
namespace openai {
  inline void start() {}
}

#endif // AISTREAM_HPP_
