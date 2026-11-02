#include <arapuca/core/event_bus.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

namespace {

using arapuca::core::Event;
using arapuca::core::EventBus;
using arapuca::core::EventType;
using namespace std::chrono_literals;

Event make_event() {
    return Event::make(EventType::SshCommand, "arapuca-test");
}

TEST(EventBus, PublishAndConsume) {
    EventBus bus(10);
    EXPECT_TRUE(bus.publish(make_event()));
    EXPECT_EQ(1U, bus.size());

    std::vector<Event> out;
    EXPECT_EQ(1U, bus.consume(out, 10, 10ms));
    EXPECT_EQ(1U, out.size());
    EXPECT_EQ(0U, bus.size());
}

// The bound is a safety control, not a tuning knob: an unbounded queue turns a
// flood into an out of memory kill on a 1 GB machine.
TEST(EventBus, RefusesWhenFullAndCountsTheDrop) {
    EventBus bus(3);
    EXPECT_TRUE(bus.publish(make_event()));
    EXPECT_TRUE(bus.publish(make_event()));
    EXPECT_TRUE(bus.publish(make_event()));

    EXPECT_FALSE(bus.publish(make_event()));
    EXPECT_FALSE(bus.publish(make_event()));

    EXPECT_EQ(3U, bus.size());
    EXPECT_EQ(2U, bus.dropped());
}

TEST(EventBus, ZeroCapacityIsClampedNotFatal) {
    EventBus bus(0);
    EXPECT_EQ(1U, bus.capacity());
    EXPECT_TRUE(bus.publish(make_event()));
    EXPECT_FALSE(bus.publish(make_event()));
}

TEST(EventBus, ConsumeRespectsTheBatchLimit) {
    EventBus bus(10);
    for (int i = 0; i < 7; ++i) {
        EXPECT_TRUE(bus.publish(make_event()));
    }

    std::vector<Event> out;
    EXPECT_EQ(3U, bus.consume(out, 3, 10ms));
    EXPECT_EQ(4U, bus.size());
}

TEST(EventBus, ConsumeReturnsZeroOnTimeoutWhenEmpty) {
    EventBus bus(10);
    std::vector<Event> out;
    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(0U, bus.consume(out, 10, 50ms));
    EXPECT_GE(std::chrono::steady_clock::now() - started, 40ms);
}

TEST(EventBus, CloseRefusesFurtherPublishes) {
    EventBus bus(10);
    bus.close();
    EXPECT_TRUE(bus.closed());
    EXPECT_FALSE(bus.publish(make_event()));
    EXPECT_EQ(1U, bus.dropped());
}

TEST(EventBus, CloseWakesABlockedConsumer) {
    EventBus bus(10);
    std::atomic<bool> returned{false};

    std::thread consumer([&] {
        std::vector<Event> out;
        (void)bus.consume(out, 10, 10s);
        returned = true;
    });

    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(returned.load());
    bus.close();
    consumer.join();
    EXPECT_TRUE(returned.load());
}

TEST(EventBus, ClosedBusStillDrainsWhatIsQueued) {
    EventBus bus(10);
    EXPECT_TRUE(bus.publish(make_event()));
    bus.close();

    std::vector<Event> out;
    EXPECT_EQ(1U, bus.consume(out, 10, 10ms));
}

TEST(EventBus, ManyProducersOneConsumerLoseNothing) {
    constexpr std::size_t kProducers = 8;
    constexpr std::size_t kPerProducer = 500;
    EventBus bus(kProducers * kPerProducer);

    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (std::size_t i = 0; i < kProducers; ++i) {
        producers.emplace_back([&bus] {
            for (std::size_t n = 0; n < kPerProducer; ++n) {
                (void)bus.publish(make_event());
            }
        });
    }
    for (auto& thread : producers) {
        thread.join();
    }

    std::vector<Event> out;
    while (bus.consume(out, 128, 10ms) > 0) {
    }
    EXPECT_EQ(kProducers * kPerProducer, out.size());
    EXPECT_EQ(0U, bus.dropped());
}

}  // namespace
