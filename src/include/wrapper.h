#pragma once

#include "rust/cxx.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"
#include "modsecurity/transaction.h"

namespace modsecurity {
    std::unique_ptr<modsecurity::ModSecurity> new_modsecurity();
    std::unique_ptr<modsecurity::Rules> new_rules();
    std::unique_ptr<std::string> get_parser_error(modsecurity::Rules &rules);
    std::unique_ptr<modsecurity::Transaction> new_transaction(ModSecurity &modsec, Rules &rules);
}
