// Tests of the C++ wrapper against the ciplink-sim binary over TCP:
//   test_ciplink <logix port> <slc port> [credentials fixture]
// with the simulator serving tools/sim/example_controller.json and tools/sim/example_slc.json; the fixture is
// crates/ciplink/tests/fixtures/logix_descriptions.json (synthetic metadata credentials).
#include "ciplink.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <cmath>
#include <fstream>
#include <iterator>
#include <functional>
#include <iostream>
#include <string>
#include <thread>

namespace {

int failures = 0;
int checks = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        ++checks;                                                                      \
        if (!(cond)) {                                                                 \
            ++failures;                                                                \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n"; \
        }                                                                              \
    } while (0)

template <class F>
void expect_error(CiplinkStatus status, F f) {
    ++checks;
    try {
        f();
        ++failures;
        std::cerr << "expected ciplink::Error " << int(status) << ", nothing thrown\n";
    } catch (const ciplink::Error& e) {
        if (e.status() != status) {
            ++failures;
            std::cerr << "expected status " << int(status) << ", got " << int(e.status()) << ": " << e.what() << "\n";
        } else if (std::string(e.what()).empty()) {
            ++failures;
            std::cerr << "error without a message\n";
        }
    }
}

void run(const char* name, const std::function<void()>& f) {
    int before = failures;
    try {
        f();
    } catch (const std::exception& e) {
        ++failures;
        std::cerr << name << ": unexpected exception: " << e.what() << "\n";
    }
    std::cout << (failures == before ? "ok   " : "FAIL ") << name << "\n";
}

std::string logix_path, slc_path;

std::string fixture_path;

/// A hex field of the synthetic credentials in the reference fixture (logix_descriptions.json).
std::vector<uint8_t> fixture_bytes(const std::string& field) {
    std::ifstream in(fixture_path, std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    size_t at = text.find("\"credentials\"");
    if (at == std::string::npos) return {};
    at = text.find("\"" + field + "\": \"", at);
    if (at == std::string::npos) return {};
    at += field.size() + 5;
    std::vector<uint8_t> out;
    while (at + 1 < text.size() && text[at] != '"') {
        out.push_back(uint8_t(std::stoul(text.substr(at, 2), nullptr, 16)));
        at += 2;
    }
    return out;
}

using ciplink::Array;
using ciplink::Bytes;
using ciplink::Struct;
using ciplink::Value;

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: test_ciplink <logix port> <slc port>\n";
        return 2;
    }
    logix_path = std::string("127.0.0.1:") + argv[1];
    slc_path = std::string("127.0.0.1:") + argv[2];
    if (argc > 3) fixture_path = argv[3];

    run("json_roundtrip", [] {
        Value v = Struct{{"a", int64_t(-5)},
                         {"b", Array{Value(true), Value(1.5), Value("x\"\n")}},
                         {"c", Bytes{{0x00, 0xab}}},
                         {"d", uint64_t(18446744073709551615ULL)},
                         {"e", std::nan("")}};
        std::string j = ciplink::to_json(v);
        Value back = ciplink::parse_json(j);
        CHECK(ciplink::to_json(back) == j);
        CHECK(back["a"].as_int() == -5);
        CHECK(back["b"][2].as_string() == "x\"\n");
        CHECK(back["c"].get<Bytes>().data.size() == 2);
        CHECK(back["d"].as_uint() == 18446744073709551615ULL);
        CHECK(std::isnan(back["e"].as_double()));
        CHECK(ciplink::parse_json("\"\\u00e9\\ud83d\\ude00\"").as_string() == "\xc3\xa9\xf0\x9f\x98\x80");
        CHECK(ciplink::parse_json("2.0").is<double>());
        CHECK(ciplink::parse_json("2").is<int64_t>());
    });

    run("read_atomic", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        CHECK(plc.connected());
        auto r = plc.read({"dint1", "sint1", "lint1", "ulint1", "real1", "lreal1"});
        CHECK(r.size() == 6);
        CHECK(r[0] && r[0].value.as_int() == 2147483647 && r[0].type == std::string("DINT"));
        CHECK(r[1].value.as_int() == 100);
        CHECK(r[2].value.as_int() == INT64_MIN);
        CHECK(r[3].value.as_uint() == 18446744073709551615ULL);
        CHECK(r[4].value.as_double() == 3.25);
        CHECK(r[5].value.as_double() == 1e100);
    });

    run("write_atomic", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        CHECK(plc.write_tag("dint1", 1234));
        CHECK(plc.write_tag("real1", 0.5));
        CHECK(plc.write_tag("lint1", int64_t(-9000000000LL)));
        CHECK(plc.read_tag("dint1").value.as_int() == 1234);
        CHECK(plc.read_tag("real1").value.as_double() == 0.5);
        CHECK(plc.read_tag("lint1").value.as_int() == -9000000000LL);
    });

    run("array", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        auto t = plc.read_tag("dint_ary[1]{3}");
        CHECK(t.value == Value(Array{100, 200, 300}));
        CHECK(plc.write_tag("dint_ary[0]{2}", Array{7, 8}));
        CHECK(plc.read_tag("dint_ary[0]{2}").value == Value(Array{7, 8}));
        CHECK(plc.read_tag("real_ary{5}").value.as_array().size() == 5);
    });

    run("struct", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        auto t = plc.read_tag("udt1");
        CHECK(t && t.value["dint"].as_int() == 10);
        CHECK(t.type == std::string("AtomicUDT"));
        Struct s{{"bool", false}, {"sint", 1}, {"int", 2}, {"dint", 3}, {"lint", 4}, {"real", 0.25}};
        CHECK(plc.write_tag("udt1", s));
        CHECK(plc.read_tag("udt1.real").value.as_double() == 0.25);
        CHECK(plc.read_tag("timer1.PRE").value.as_int() == 5000);
    });

    run("string", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        CHECK(plc.read_tag("str1").value.as_string() == "Hello Logix");
        CHECK(plc.write_tag("str20", "hi there"));
        CHECK(plc.read_tag("str20").value.as_string() == "hi there");
        auto too_long = plc.write_tag("str20", std::string(30, 'x'));
        CHECK(!too_long && too_long.error);
    });

    run("bit", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        CHECK(plc.read_tag("bool1").value.as_bool() == true);
        CHECK(plc.write_tag("bool2", true));
        CHECK(plc.read_tag("bool2").value.as_bool() == true);
        CHECK(plc.write_tag("dint_ary[5].3", true));
        CHECK(plc.read_tag("dint_ary[5].3").value.as_bool() == true);
        CHECK(plc.read_tag("bool_ary[0]").value.as_bool() == true);
    });

    run("tag_errors_are_data", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        auto r = plc.read({"no_such_tag", "int1"});
        CHECK(!r[0] && r[0].error && r[0].error->kind == "not_found");
        CHECK(r[0].value.is_null());
        CHECK(r[1] && r[1].value.as_int() == -1234);
        auto w = plc.write_tag("sint1", 1000);
        CHECK(!w && w.error->kind == "bad_value");
    });

    run("call_errors_throw", [] {
        expect_error(CIPLINK_STATUS_INVALID_ARGUMENT, [] { ciplink::Logix plc("127.0.0.1", "{bad json"); });
        expect_error(CIPLINK_STATUS_COMM, [] {
            ciplink::Logix plc("127.0.0.1:1", R"({"socket_timeout": 1})");
            plc.open();
        });
        ciplink::Cip cip(logix_path);
        expect_error(CIPLINK_STATUS_UNSUPPORTED, [&] {
            char* out = nullptr;
            ciplink::detail::check(ciplink_tags(cip.handle(), &out));
        });
    });

    run("tags_info_and_time", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        Value tags = ciplink::parse_json(plc.tags_json());
        CHECK(tags["dint1"]["data_type"].as_string() == "DINT");
        CHECK(ciplink::parse_json(plc.info_json())["product_name"].as_string() == "1756-SIM/A");
        CHECK(ciplink::parse_json(plc.tag_info_json("udt1.dint"))["data_type"].as_string() == "DINT");
        CHECK(ciplink::parse_json(plc.data_types_json()).as_struct().size() > 0);
        CHECK(ciplink::parse_json(plc.tag_list_json()).as_array().size() > 0);
        CHECK(plc.set_plc_time(uint64_t(1700000000000000ULL)));
        CHECK(plc.get_plc_time() >= 1700000000000000ULL);
    });

    run("generic_message", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        ciplink::Message m;
        m.service = 0x0e;  // Get Attribute Single
        m.class_code = 1;  // Identity
        m.instance = 1;
        m.attribute = 3;  // product code
        m.connected = false;
        m.name = "product_code";
        auto t = plc.generic_message(m);
        CHECK(t && t.tag == "product_code");
        CHECK(t.value.get<Bytes>().data == std::vector<uint8_t>({0xa6, 0x00}));
        CHECK(ciplink::list_identity(logix_path)["product_name"].as_string() == "1756-SIM/A");
    });

    run("slc", [] {
        ciplink::Slc slc(slc_path);
        slc.open();
        CHECK(slc.write_tag("N7:1", 42));
        CHECK(slc.read_tag("N7:1").value.as_int() == 42);
        CHECK(slc.read_tag("N7:0{2}").value.as_array().size() == 2);
        CHECK(!slc.read_tag("N99:0"));
    });

    run("threads_share_a_handle", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        std::vector<std::thread> threads;
        int bad[4] = {0, 0, 0, 0};
        for (int i = 0; i < 4; ++i) {
            threads.emplace_back([&, i] {
                for (int k = 0; k < 20; ++k)
                    if (plc.read_tag("int1").value.as_int() != -1234) ++bad[i];
            });
        }
        for (auto& t : threads) t.join();
        CHECK(bad[0] + bad[1] + bad[2] + bad[3] == 0);
    });

    run("move_and_close", [] {
        ciplink::Logix a(logix_path);
        a.open();
        ciplink::Logix b = std::move(a);
        CHECK(b.connected());
        b.close();
        CHECK(!b.connected());
        CHECK(!ciplink::version().empty());
    });

    run("controller_info", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        CHECK(plc.get_plc_name() == "SimPLC");
        CHECK(plc.get_plc_info()["keyswitch"].as_string() == "REMOTE RUN");
        CHECK(plc.get_module_info(1)["product_name"].as_string() == "1756-EN2T/D");
        CHECK(plc.tag_table_version().as_array().size() == 5);
        CHECK(!plc.check_tag_table());
        CHECK(plc.get_tag_description("dint1").tag == "dint1.@Description");
    });

    run("slc_directory_and_datalog", [] {
        ciplink::Slc slc(slc_path);
        slc.open();
        CHECK(slc.get_processor_type().as_string() == "1747-L552");
        CHECK(slc.get_file_directory()["N7"]["elements"].as_int() > 0);
        CHECK(slc.get_datalog_queue(2, 1)[0].as_string() == "2026/10/19,10:00:00,1,2");
        expect_error(CIPLINK_STATUS_UNSUPPORTED, [&] {
            bool b = false;
            ciplink::detail::check(ciplink_check_tag_table(slc.handle(), &b));
        });
    });

    run("raw_send", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        // Get Attribute Single of the identity's product code; the reply frame ends with 8e 00 00 00 a6 00
        const std::vector<uint8_t> request = {0x0e, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x03};
        const std::vector<uint8_t> tail = {0x8e, 0x00, 0x00, 0x00, 0xa6, 0x00};
        auto ends_with_tail = [&](const std::vector<uint8_t>& f) {
            return f.size() > tail.size() && std::equal(tail.begin(), tail.end(), f.end() - tail.size());
        };
        auto u = plc.send_unconnected(request);
        CHECK(u.size() > 24 && u[0] == 0x6f && ends_with_tail(u));
        auto c = plc.send_connected(request);
        CHECK(c.size() > 24 && c[0] == 0x70 && ends_with_tail(c));
        ciplink::Slc slc(slc_path);
        slc.open();
        CHECK(slc.send_unconnected(request)[0] == 0x6f);
        plc.close();
        expect_error(CIPLINK_STATUS_COMM, [&] { plc.send_unconnected(request); });
    });

    run("connection_size_and_socket_timeout", [] {
        ciplink::Logix plc(logix_path);
        CHECK(plc.connection_size() == 4000);
        plc.set_connection_size(500);
        CHECK(plc.connection_size() == 500);
        expect_error(CIPLINK_STATUS_INVALID_ARGUMENT, [&] { plc.set_connection_size(0); });
        plc.open();
        CHECK(plc.read_tag("big_ary{2000}").value.as_array().size() == 2000);
        expect_error(CIPLINK_STATUS_REQUEST, [&] { plc.set_connection_size(4000); });
        plc.close();
        plc.set_connection_size(4000);
        CHECK(plc.connection_size() == 4000);

        CHECK(plc.socket_timeout() == 5.0);
        plc.set_socket_timeout(std::nullopt);
        CHECK(!plc.socket_timeout());
        expect_error(CIPLINK_STATUS_INVALID_ARGUMENT, [&] { plc.set_socket_timeout(0.0); });
        plc.open();
        plc.set_socket_timeout(2.5);
        CHECK(plc.socket_timeout() == 2.5);
        CHECK(plc.read_tag("dint1"));
    });

    run("tag_list_program_cache_filter", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        auto program = ciplink::parse_json(plc.tag_list_json(std::string("MainProgram"), false));
        CHECK(program.as_array().size() > 0);
        bool all_program = true;
        for (auto& t : program.as_array())
            all_program = all_program && t["tag_name"].as_string().rfind("Program:MainProgram.", 0) == 0;
        CHECK(all_program);
        CHECK(ciplink::parse_json(plc.tags_json())["dint1"]["data_type"].as_string() == "DINT");
        auto filtered = ciplink::parse_json(plc.tag_list_json(std::nullopt, false, "dint"));
        bool all_dint = filtered.as_array().size() > 0;
        for (auto& t : filtered.as_array()) all_dint = all_dint && t["tag_name"].as_string().rfind("dint", 0) == 0;
        CHECK(all_dint);
        plc.tag_list_json(std::string("MainProgram"), true);
        bool replaced = true;
        Value cached = ciplink::parse_json(plc.tags_json());
        for (auto& kv : cached.as_struct())
            replaced = replaced && kv.first.rfind("Program:MainProgram.", 0) == 0;
        CHECK(replaced && cached.as_struct().size() > 0);
    });

    run("authenticate_metadata_with_credentials", [] {
        auto cert = fixture_bytes("certificate");
        auto key = fixture_bytes("key");
        CHECK(!cert.empty() && !key.empty());
        ciplink::Logix plc(logix_path);
        plc.open();
        auto t = plc.authenticate_metadata(cert, key);
        CHECK(t && t.value.as_bool() && t.tag == "metadata_authentication");
        CHECK(plc.authenticate_metadata());
        std::vector<uint8_t> short_key(key.begin(), key.begin() + 10);
        expect_error(CIPLINK_STATUS_REQUEST, [&] { plc.authenticate_metadata(cert, short_key); });
        expect_error(CIPLINK_STATUS_REQUEST, [&] { plc.authenticate_metadata({}, {}); });
    });

    run("trend_samples_tags_until_closed", [] {
        ciplink::Logix plc(logix_path);
        plc.open();
        ciplink::Trend trend = plc.trend({"sint1", "uint1", "real1", "timer1.EN"}, 5);
        auto pens = trend.pens();
        CHECK(pens.size() == 4 && pens[1].tag == "uint1" && pens[3].type == "BOOL");
        CHECK(trend.running());
        std::vector<ciplink::TrendSample> samples;
        for (int i = 0; i < 400 && samples.size() < 2; ++i) {
            auto batch = trend.read();
            samples.insert(samples.end(), batch.begin(), batch.end());
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        CHECK(samples.size() >= 2);
        if (samples.size() >= 2) {
            CHECK(samples[0].values.size() == 4);
            CHECK(samples[0].values[0].as_int() == 100);
            CHECK(samples[0].values[1].as_int() == 60000);
            CHECK(samples[0].values[2] == plc.read_tag("real1").value);  // an earlier test writes it
            CHECK(samples[0].values[3].as_bool());
            CHECK(samples[0].timestamp_us == trend.start_time_us() + samples[0].elapsed_us);
            CHECK(std::llabs(int64_t(samples[1].elapsed_us - samples[0].elapsed_us) - 5000) < 128);
        }
        trend.close();
        CHECK(!trend.running());
        CHECK(!trend.error());
        expect_error(CIPLINK_STATUS_REQUEST, [&] { plc.trend({"lint1"}); });
        expect_error(CIPLINK_STATUS_INVALID_ARGUMENT, [&] { plc.trend({"dint1"}, 0); });
    });

    run("browse_ports_slots_and_network", [] {
        ciplink::Cip cip(logix_path);
        cip.open();
        CHECK(cip.get_identity()["product_name"].as_string() == "1756-SIM/A");
        CHECK(cip.get_identity("bp/1")["product_name"].as_string() == "1756-EN2T/D");
        CHECK(cip.get_app().is_null());  // a controller is no ciplink device
        Value ports = cip.get_ports();
        CHECK(ports[0]["type_name"].as_string() == "Backplane");
        CHECK(ports[0]["nodes"].as_array().size() == 10);
        CHECK(ports[1]["type_name"].as_string() == "EtherNet/IP");
        CHECK(ports[1]["ip"].as_string() == "192.168.1.10");

        Value slots = cip.browse_port("", 1, std::vector<std::string>{"1", "2", "3"}, 2);
        CHECK(slots.as_array().size() == 3);
        CHECK(slots[0]["route"].as_string() == "1/1");
        CHECK(slots[1]["identity"]["product_name"].as_string() == "1756-IB16/A");
        CHECK(slots[2]["identity"].is_null() && slots[2]["error"].is<std::string>());

        Value subnet = cip.browse_port("", 2);  // the port's own addresses: its subnet
        CHECK(subnet.as_array().size() == 254);
        std::vector<std::string> found;
        for (auto& n : subnet.as_array())
            if (!n["identity"].is_null()) found.push_back(n["route"].as_string());
        CHECK(found == std::vector<std::string>{"2/192.168.1.20"});

        size_t seen = 0;
        std::string first;
        cip.scan_port("", 2, [&](const Value& n) {
            ++seen;
            if (n["identity"].is_null()) return true;
            first = n["identity"]["product_name"].as_string();
            return false;
        }, std::nullopt, 4);
        CHECK(first == "1734-AENTR/C");
        CHECK(seen < 254);
        bool thrown = false;
        try {
            cip.scan_port("", 1, [](const Value&) -> bool { throw std::runtime_error("stop"); });
        } catch (const std::runtime_error& e) {
            thrown = std::string(e.what()) == "stop";
        }
        CHECK(thrown);
    });

    run("tag_server_starts_and_stops", [&] {
        namespace fs = std::filesystem;
        fs::path dir = fs::temp_directory_path() / "ciplink-cpp-server";
        fs::create_directories(dir);
        std::ofstream(dir / "tags.json") << R"({"Speed": "REAL"})";
        std::ofstream(dir / "tagserver.toml") << "[server]\naudit_log = \"\"\npages_file = \"\"\n"
                                                 "[plc.P]\npath = \"192.0.2.1\"\nmock_tags = \"tags.json\"\n"
                                                 "[token.t]\nsecret = \"s\"\n";
        ciplink::Server server((dir / "tagserver.toml").string(), true, std::nullopt, uint16_t(0));
        CHECK(server.address().rfind("127.0.0.1:", 0) == 0);
        server.stop();
        expect_error(CIPLINK_STATUS_INVALID_ARGUMENT, [] { ciplink::Server("no/such/tagserver.toml"); });
    });

    std::cout << checks << " checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
