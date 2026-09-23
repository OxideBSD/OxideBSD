// Seeded at /hello.cpp -- the on-target C++ proof: `clang++ -static -o /hello-cpp.elf /hello.cpp`,
// by hand at the hush prompt or via tests/clangxx_syscall_smoke.rs. Each section checks itself;
// any failure flips the exit status, so the smoke test only has to look at that.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <numeric>
#include <stdexcept>
#include <string>
#include <thread>
#include <typeinfo>
#include <vector>

namespace fs = std::filesystem;

static int failures = 0;

static void check(bool ok, const char *what) {
    std::cout << (ok ? "PASS " : "FAIL ") << what << '\n';
    if (!ok)
        ++failures;
}

// iostream + STL + templates
template <typename T> static T sum(const std::vector<T> &v) {
    return std::accumulate(v.begin(), v.end(), T{});
}

static void stl() {
    std::vector<int> v{5, 3, 9, 1, 7};
    std::sort(v.begin(), v.end());
    check(v == std::vector<int>{1, 3, 5, 7, 9}, "std::sort");
    check(sum(v) == 25, "template sum");

    std::map<std::string, int> m;
    for (const char *w : {"ox", "ide", "bsd", "ox"})
        ++m[w];
    check(m.size() == 3 && m["ox"] == 2, "std::map");

    std::string s = "OxideBSD";
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    check(s == "OXIDEBSD", "std::string + lambda");
}

// Exceptions + RTTI: a throw that unwinds through real frames exercises libunwind's
// .eh_frame_hdr lookup in a static binary, not just a same-frame catch.
struct Base {
    virtual ~Base() = default;
};
struct Derived : Base {
    int payload = 42;
};

[[gnu::noinline]] static void thrower(int depth) {
    if (depth == 0)
        throw std::runtime_error("deep throw");
    thrower(depth - 1);
}

static void exceptions_rtti() {
    bool caught = false;
    try {
        thrower(8);
    } catch (const std::exception &e) {
        caught = std::string(e.what()) == "deep throw";
    }
    check(caught, "throw/catch across 8 frames");

    bool caught_rethrow = false;
    try {
        try {
            throw 7;
        } catch (...) {
            throw;
        }
    } catch (int n) {
        caught_rethrow = n == 7;
    }
    check(caught_rethrow, "rethrow");

    Derived d;
    Base *b = &d;
    auto *dp = dynamic_cast<Derived *>(b);
    check(dp && dp->payload == 42, "dynamic_cast");
    check(typeid(*b) == typeid(Derived), "typeid");
}

// std::thread + mutex: real clone(2) + futex(2) under libc++'s pthread layer.
static void threads() {
    constexpr int kThreads = 4, kIters = 1000;
    std::mutex mu;
    long counter = 0;
    std::vector<std::thread> pool;
    for (int t = 0; t < kThreads; ++t)
        pool.emplace_back([&] {
            for (int i = 0; i < kIters; ++i) {
                std::lock_guard<std::mutex> g(mu);
                ++counter;
            }
        });
    for (auto &th : pool)
        th.join();
    check(counter == kThreads * kIters, "std::thread x4 + std::mutex");
}

// std::filesystem over oxfs.
static void filesystem() {
    std::error_code ec;
    const fs::path root = "/tmp-cxx-fs";
    fs::remove_all(root, ec);
    check(fs::create_directories(root / "a" / "b", ec) && !ec, "create_directories");

    {
        std::ofstream out(root / "a" / "b" / "file.txt");
        out << "twelve bytes";
    }
    check(fs::file_size(root / "a" / "b" / "file.txt", ec) == 12 && !ec, "ofstream + file_size");

    int entries = 0;
    for (const auto &e : fs::recursive_directory_iterator(root, ec)) {
        (void)e;
        ++entries;
    }
    check(entries == 3 && !ec, "recursive_directory_iterator");

    fs::remove_all(root, ec);
    check(!fs::exists(root), "remove_all");
}

int main() {
    std::cout << "hello, OxideBSD, from C++\n";
    stl();
    exceptions_rtti();
    threads();
    filesystem();
    std::cout << (failures ? "SOME C++ CHECKS FAILED\n" : "all C++ checks passed\n");
    return failures ? 1 : 0;
}
