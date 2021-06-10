#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"
#include "modsecurity/transaction.h"

namespace modsecurity {
    std::unique_ptr<modsecurity::ModSecurity> new_modsecurity() {
        return std::make_unique<modsecurity::ModSecurity>();
    }

    std::unique_ptr<modsecurity::Rules> new_rules() {
        return std::unique_ptr<Rules>(msc_create_rules_set());
    }

    std::unique_ptr<std::string> get_parser_error(modsecurity::Rules &rules) {
        std::string parseError = rules.getParserError();
        return std::make_unique<std::string>(std::move(parseError));
    }

    std::unique_ptr<modsecurity::Transaction> new_transaction(ModSecurity &modsec, Rules &rules) {
        return std::make_unique<modsecurity::Transaction>(&modsec, &rules, nullptr);
    }
}
