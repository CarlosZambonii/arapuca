#include <arapuca/capture/hashing.hpp>

#include <openssl/evp.h>

#include <array>
#include <memory>

namespace arapuca::capture {
namespace {

struct ContextDeleter {
    void operator()(EVP_MD_CTX* context) const noexcept {
        if (context != nullptr) {
            EVP_MD_CTX_free(context);
        }
    }
};

std::string hex_digest(std::string_view data, const EVP_MD* algorithm) {
    const std::unique_ptr<EVP_MD_CTX, ContextDeleter> context(EVP_MD_CTX_new());
    if (!context) {
        return {};
    }
    if (EVP_DigestInit_ex(context.get(), algorithm, nullptr) != 1) {
        return {};
    }
    if (!data.empty() && EVP_DigestUpdate(context.get(), data.data(), data.size()) != 1) {
        return {};
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &length) != 1) {
        return {};
    }

    static constexpr std::array<char, 16> kHex = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string out;
    out.reserve(static_cast<std::size_t>(length) * 2);
    for (unsigned int i = 0; i < length; ++i) {
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
        out.push_back(kHex[(digest[i] >> 4U) & 0x0FU]);
        out.push_back(kHex[digest[i] & 0x0FU]);
        // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    }
    return out;
}

}  // namespace

std::string sha256_hex(std::string_view data) {
    return hex_digest(data, EVP_sha256());
}

std::string md5_hex(std::string_view data) {
    return hex_digest(data, EVP_md5());
}

Digests digests_of(std::string_view data) {
    return {sha256_hex(data), md5_hex(data), data.size()};
}

}  // namespace arapuca::capture
