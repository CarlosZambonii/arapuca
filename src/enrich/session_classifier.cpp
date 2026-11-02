#include <arapuca/enrich/session_classifier.hpp>

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

namespace arapuca::enrich {
namespace {

// Weights. They are small integers over ten rather than tuned constants,
// because the point is a readable explanation on a dashboard, not accuracy to
// the third decimal.
constexpr double kMachineSpeedWeight = -0.50;  // gaps a person cannot produce
constexpr double kFastWeight = -0.20;          // fast, but humanly possible
constexpr double kDeliberateWeight = 0.30;     // long pauses, reading output
constexpr double kMetronomeWeight = -0.30;     // almost no variation
constexpr double kIrregularWeight = 0.20;      // varied rhythm
constexpr double kLineEditingWeight = 0.50;    // backspace or arrows
constexpr double kTabCompletionWeight = 0.40;  // tab pressed
constexpr double kTypoWeight = 0.20;           // unrecognized commands

constexpr double kMachineSpeedMs = 200.0;
constexpr double kFastMs = 600.0;
constexpr double kDeliberateMs = 1200.0;
constexpr double kMetronomeCv = 0.20;
constexpr double kIrregularCv = 0.60;

void note(std::ostringstream& reason, bool& first, const std::string& text) {
    if (!first) {
        reason << ", ";
    }
    reason << text;
    first = false;
}

}  // namespace

std::string_view to_string(SessionClass verdict) {
    // clang-format off
    switch (verdict) {
        case SessionClass::Bot:         return "bot";
        case SessionClass::LikelyHuman: return "likely_human";
        case SessionClass::Unknown:     return "unknown";
    }
    // clang-format on
    return "unknown";
}

double median(std::vector<std::int64_t> values) {
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end());
    const std::size_t middle = values.size() / 2;
    if (values.size() % 2 == 1) {
        return static_cast<double>(values[middle]);
    }
    return (static_cast<double>(values[middle - 1]) + static_cast<double>(values[middle])) / 2.0;
}

double coefficient_of_variation(const std::vector<std::int64_t>& values) {
    if (values.size() < 2) {
        return 0.0;
    }

    const double sum =
        std::accumulate(values.begin(), values.end(), 0.0, [](double acc, std::int64_t value) {
            return acc + static_cast<double>(value);
        });
    const double mean = sum / static_cast<double>(values.size());
    if (mean <= 0.0) {
        return 0.0;
    }

    double variance = 0.0;
    for (const std::int64_t value : values) {
        const double delta = static_cast<double>(value) - mean;
        variance += delta * delta;
    }
    variance /= static_cast<double>(values.size());

    return std::sqrt(variance) / mean;
}

Classification classify_session(const SessionSignals& signals) {
    Classification result;

    if (signals.command_count < kMinimumCommandsForVerdict) {
        result.verdict = SessionClass::Unknown;
        result.reason = "too few commands for a verdict";
        return result;
    }

    std::ostringstream reason;
    bool first = true;
    double score = 0.0;

    const double gap = median(signals.inter_command_gaps_ms);
    if (!signals.inter_command_gaps_ms.empty()) {
        if (gap < kMachineSpeedMs) {
            score += kMachineSpeedWeight;
            note(reason,
                 first,
                 "median gap " + std::to_string(static_cast<long>(gap)) +
                     "ms is below human typing speed");
        } else if (gap < kFastMs) {
            score += kFastWeight;
            note(reason,
                 first,
                 "median gap " + std::to_string(static_cast<long>(gap)) + "ms is fast");
        } else if (gap > kDeliberateMs) {
            score += kDeliberateWeight;
            note(reason,
                 first,
                 "median gap " + std::to_string(static_cast<long>(gap)) +
                     "ms suggests reading output");
        }
    }

    // Rhythm needs enough samples to mean anything. Below the threshold the
    // spread of two or three gaps says nothing about whether a person or a
    // script produced them.
    if (signals.inter_command_gaps_ms.size() >= kMinimumGapsForRhythm) {
        const double variation = coefficient_of_variation(signals.inter_command_gaps_ms);
        if (variation < kMetronomeCv) {
            score += kMetronomeWeight;
            note(reason, first, "timing is near constant, which is scripted");
        } else if (variation > kIrregularCv) {
            score += kIrregularWeight;
            note(reason, first, "timing is irregular");
        }
    }

    if (signals.used_tab_completion) {
        score += kTabCompletionWeight;
        note(reason, first, "tab completion used");
    }
    if (signals.used_line_editing) {
        score += kLineEditingWeight;
        note(reason, first, "line editing used");
    }
    if (signals.unknown_commands > 0) {
        score += kTypoWeight;
        note(reason,
             first,
             std::to_string(signals.unknown_commands) +
                 " unrecognized commands, possibly typing mistakes");
    }

    score = std::clamp(score, -1.0, 1.0);
    result.score = score;

    if (score <= -kVerdictThreshold) {
        result.verdict = SessionClass::Bot;
    } else if (score >= kVerdictThreshold) {
        result.verdict = SessionClass::LikelyHuman;
    } else {
        result.verdict = SessionClass::Unknown;
    }

    result.reason = first ? "no distinguishing signals" : reason.str();
    return result;
}

}  // namespace arapuca::enrich
