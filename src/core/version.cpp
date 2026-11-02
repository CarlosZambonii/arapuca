#include <arapuca/version.hpp>

#include <string>

namespace arapuca {

std::string build_banner() {
    std::string banner;
    banner.reserve(64);
    banner.append(kProjectName);
    banner.append(" ");
    banner.append(kVersion);
    banner.append(" (event schema v");
    banner.append(std::to_string(kEventSchemaVersion));
    banner.append(")");
    return banner;
}

}  // namespace arapuca
