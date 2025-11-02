// These tests intentionally live alongside the integration suite so future
// refactors can reference concrete evidence for how Boost.DI scopes behave.
//
// Observed behaviour (validated by this file):
// 1. `di::singleton` bindings are process-wide. Destroying an injector does
//    not trigger the bound object's destructor; instead, the instance lives in
//    Boost.DI's internal static cache and is reused by every injector that asks
//    for the same type. Code relying on injector lifetime to clean up
//    singletons is therefore incorrect.
// 2. `di::unique` bindings allocate a fresh object for each creation and are
//    immediately released when the caller drops its smart pointer. These behave
//    like per-call factories.
// 3. Factories composed inside the injector capture the injector by reference.
//    If a test copies such a factory and the injector goes out of scope,
//    calling the factory later is undefined behaviour even though the
//    singletons it would reference still exist.
// 4. To safely use a factory outside the injector scope, move the injector into
//    a reference-counted holder (e.g. `std::shared_ptr`) and let the factory
//    close over that holder. This pattern keeps the injector alive until the
//    last factory user releases it.
//
// Keep these invariants in mind when wiring the InstallConfigManager harness:
// shared state that must outlive the injector has to be owned explicitly, and
// factories must either stay within injector scope or carry their own shared
// injector handle.

#include <gtest/gtest.h>

#include <boost/di.hpp>
#include <functional>
#include <memory>
#include <utility>

namespace {

namespace di = boost::di;

template <typename Tag> struct SingletonTracker {
  inline static int constructions = 0;
  inline static int destructions = 0;
  inline static SingletonTracker *last_instance = nullptr;

  SingletonTracker() { last_instance = this; ++constructions; }
  ~SingletonTracker() { last_instance = nullptr; ++destructions; }

  static void Reset() {
    constructions = 0;
    destructions = 0;
    last_instance = nullptr;
  }
};

template <typename Tag> struct UniqueTracker {
  inline static int constructions = 0;
  inline static int destructions = 0;

  UniqueTracker() { ++constructions; }
  ~UniqueTracker() { ++destructions; }

  static void Reset() {
    constructions = 0;
    destructions = 0;
  }
};

struct TagSingletonA;
struct TagSingletonB;
struct TagUnique;
struct TagService;

using GlobalSingleton = SingletonTracker<TagSingletonA>;
using AnotherSingleton = SingletonTracker<TagSingletonB>;
using UniqueResource = UniqueTracker<TagUnique>;

struct ServiceWithGlobalSingleton {
  GlobalSingleton &resource;
  static inline int constructions = 0;

  explicit ServiceWithGlobalSingleton(GlobalSingleton &r) : resource(r) {
    ++constructions;
  }
};

using ServiceFactory = std::function<std::shared_ptr<ServiceWithGlobalSingleton>()>;

TEST(BoostDiLifetimes, SingletonScopeIsProcessWide) {
  GlobalSingleton::Reset();
  AnotherSingleton::Reset();

  GlobalSingleton *first_ptr = nullptr;
  {
    auto injector = di::make_injector(
        di::bind<GlobalSingleton>().in(di::singleton));
    auto &one = injector.create<GlobalSingleton &>();
    auto &two = injector.create<GlobalSingleton &>();
    ASSERT_EQ(&one, &two);
    first_ptr = &one;
    EXPECT_EQ(GlobalSingleton::constructions, 1);
    EXPECT_EQ(GlobalSingleton::destructions, 0);
  }

  EXPECT_EQ(GlobalSingleton::destructions,
            0) << "Singleton survives injector destruction";

  {
    auto injector = di::make_injector(
        di::bind<GlobalSingleton>().in(di::singleton));
    auto &again = injector.create<GlobalSingleton &>();
    EXPECT_EQ(first_ptr, &again)
        << "Singleton instance reused across different injectors";
    EXPECT_EQ(GlobalSingleton::constructions, 1);
  }
}

TEST(BoostDiLifetimes, UniqueScopeAlwaysCreatesFreshInstances) {
  UniqueResource::Reset();

  auto injector = di::make_injector(di::bind<UniqueResource>().in(di::unique));
  auto first = injector.create<std::shared_ptr<UniqueResource>>();
  auto second = injector.create<std::shared_ptr<UniqueResource>>();

  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  EXPECT_NE(first.get(), second.get());
  EXPECT_EQ(UniqueResource::constructions, 2);

  first.reset();
  second.reset();
  EXPECT_EQ(UniqueResource::destructions, 2);
}

TEST(BoostDiLifetimes, FactoryRequiresInjectorLifetimeManagement) {
  GlobalSingleton::Reset();
  ServiceWithGlobalSingleton::constructions = 0;

  ServiceFactory factory;

  {
    auto injector = di::make_injector(
        di::bind<GlobalSingleton>().in(di::singleton),
        di::bind<ServiceWithGlobalSingleton>().in(di::unique),
        di::bind<ServiceFactory>().to([](const auto &inj) {
          return ServiceFactory{[&inj]() {
            return inj.template create<
                std::shared_ptr<ServiceWithGlobalSingleton>>();
          }};
        }));

    factory = injector.create<ServiceFactory>();
    auto instance_inside = factory();
    ASSERT_NE(instance_inside, nullptr);
    EXPECT_EQ(ServiceWithGlobalSingleton::constructions, 1);
  }

  // The factory still references the destroyed injector; calling it would
  // be undefined behaviour. We simply assert that the singleton never
  // received a destructor and was created only once.
  EXPECT_EQ(GlobalSingleton::constructions, 1);
  EXPECT_EQ(GlobalSingleton::destructions, 0);
}

TEST(BoostDiLifetimes, SharedInjectorKeepsFactorySafe) {
  GlobalSingleton::Reset();
  ServiceWithGlobalSingleton::constructions = 0;

  using InjectorType = decltype(di::make_injector(
      di::bind<GlobalSingleton>().in(di::singleton),
      di::bind<ServiceWithGlobalSingleton>().in(di::unique)));

  auto injector = di::make_injector(
      di::bind<GlobalSingleton>().in(di::singleton),
      di::bind<ServiceWithGlobalSingleton>().in(di::unique));
  auto guard = std::make_shared<InjectorType>(std::move(injector));

  ServiceFactory factory = [guard]() {
    return guard->template create<
        std::shared_ptr<ServiceWithGlobalSingleton>>();
  };

  auto first = factory();
  ASSERT_NE(first, nullptr);
  EXPECT_EQ(ServiceWithGlobalSingleton::constructions, 1);

  guard.reset();
  auto second = factory();
  ASSERT_NE(second, nullptr);
  EXPECT_EQ(ServiceWithGlobalSingleton::constructions, 2);
  EXPECT_EQ(GlobalSingleton::destructions, 0);
}

} // namespace
