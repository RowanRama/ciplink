// Tests of ciplink::S7Plus against the S7comm-plus simulator (tools/sim/example_s7plus.json), included by
// test_ciplink.cpp after its helpers. They run when CIPLINK_TEST_S7PLUS is "127.0.0.1:PORT" of that simulator;
// CIPLINK_TEST_S7PLUS_FINGERPRINT is the fingerprint it printed. build_and_test.sh sets both.

namespace {

void run_s7plus_tests() {
    const char* env = std::getenv("CIPLINK_TEST_S7PLUS");
    if (!env || !*env) {
        std::cout << "skip s7plus (CIPLINK_TEST_S7PLUS is not set)\n";
        return;
    }
    const std::string path = env;
    const char* fp_env = std::getenv("CIPLINK_TEST_S7PLUS_FINGERPRINT");
    const std::string sim_fingerprint = fp_env ? fp_env : "";

    run("s7plus_read_write", [&] {
        ciplink::S7Plus plc(path);
        plc.open();
        CHECK(plc.connected());
        auto r = plc.read({"Line1.Conveyor.Speed", "Line1.Status", "Mode", "Line1.Nope"});
        CHECK(r.size() == 4);
        CHECK(r[0] && r[0].value.as_double() == 1.5 && r[0].type == std::string("REAL"));
        CHECK(r[1].value.as_int() == 4660 && r[1].type == std::string("WORD"));
        CHECK(r[2].value.as_int() == 3);
        CHECK(!r[3] && r[3].error && r[3].error->kind == "not_found");
        CHECK(plc.write_tag("Line1.Label", "Batch7"));
        CHECK(plc.read_tag("Line1.Label").value.as_string() == "Batch7");
        CHECK(plc.read_tag("Line1.Recipe").value["Speed"].as_double() == 2.5);
        auto w = plc.write({{"Line1.Count", 42}, {"Line1.Count", "x"}});
        CHECK(w[0] && w[1].error && w[1].error->kind == "bad_value");
        CHECK(plc.read_tag("Line1.Count").value.as_int() == 42);
    });

    run("s7plus_browse_and_info", [&] {
        ciplink::S7Plus plc(path);
        plc.open();
        CHECK(plc.tags()["Line1"]["kind"].as_string() == "data_block");
        CHECK(plc.tags()["StartButton"]["type"].as_string() == "BOOL");
        CHECK(!plc.data_types().as_struct().empty());
        bool found = false;
        Value list = plc.tag_list();
        for (auto& s : list.as_array()) found = found || s["name"].as_string() == "Line1.Conveyor.Speed";
        CHECK(found);
        auto info = plc.tag_info("Line1.Hidden");
        CHECK(info["type"].as_string() == "INT" && !info["hmi_accessible"].as_bool());
        expect_error(CIPLINK_STATUS_REQUEST, [&] { plc.tag_info("Line1.Nope"); });
        auto cpu = plc.plc_info();
        CHECK(cpu["name"].as_string() == "PLC_Line1");
        CHECK(cpu["max_read"].as_int() == 100);
        CHECK(!plc.refresh_tags());
        expect_error(CIPLINK_STATUS_UNSUPPORTED, [&] { plc.get_identity(); });
        expect_error(CIPLINK_STATUS_UNSUPPORTED, [&] { plc.connection_size(); });
    });

    run("s7plus_fingerprint_and_pin", [&] {
        ciplink::S7Plus plc(path);
        CHECK(!plc.fingerprint());
        plc.open();
        CHECK(plc.fingerprint() && plc.fingerprint()->size() == 95);
        if (!sim_fingerprint.empty()) CHECK(*plc.fingerprint() == sim_fingerprint);
        ciplink::S7Plus pinned(path, "{\"tls_fingerprint\": \"" + *plc.fingerprint() + "\"}");
        pinned.open();
        CHECK(pinned.connected());
        ciplink::S7Plus wrong(path, "{\"tls_fingerprint\": \"" + std::string(64, '0') + "\"}");
        expect_error(CIPLINK_STATUS_COMM, [&] { wrong.open(); });
        CHECK(wrong.fingerprint() == plc.fingerprint());
        expect_error(CIPLINK_STATUS_REQUEST, [&] { ciplink::S7Plus bad(path, "{\"tls_fingerprint\": \"zz\"}"); });
    });

    run("s7plus_async_subscribe_and_events", [&] {
        // declared before the driver, so they outlive its callbacks
        std::mutex m;
        std::condition_variable cv;
        std::vector<std::string> events;
        std::vector<int64_t> seen;
        ciplink::S7Plus plc(path, "{\"keep_alive\": 1}");
        plc.on_connection([&](const ciplink::ConnectionEvent& e) {
            std::lock_guard<std::mutex> lock(m);
            events.push_back(e.event);
            cv.notify_all();
        });
        plc.open();
        CHECK(plc.connection_state() == ciplink::ConnectionState::Connected);
        {
            std::unique_lock<std::mutex> lock(m);
            CHECK(cv.wait_for(lock, std::chrono::seconds(5), [&] { return !events.empty(); }));
            CHECK(!events.empty() && events[0] == "connected");
        }

        auto a = plc.read_async({"Line1.Status"});
        auto b = plc.write_async({{"Line1.Count", 5}});
        CHECK(a.get().at(0).value.as_int() == 4660);
        CHECK(b.get().at(0));

        auto sub = plc.subscribe({"Line1.Count"}, [&](const std::vector<ciplink::Tag>& changes) {
            std::lock_guard<std::mutex> lock(m);
            for (auto& t : changes)
                if (t) seen.push_back(t.value.as_int());
            cv.notify_all();
        }, 0.05);
        {
            std::unique_lock<std::mutex> lock(m);
            CHECK(cv.wait_for(lock, std::chrono::seconds(5), [&] { return !seen.empty(); }));
        }
        plc.write_tag("Line1.Count", 6);
        {
            std::unique_lock<std::mutex> lock(m);
            CHECK(cv.wait_for(lock, std::chrono::seconds(5), [&] { return !seen.empty() && seen.back() == 6; }));
            CHECK(!seen.empty() && seen.front() == 5);
        }
        sub.close();
        plc.close();
        CHECK(plc.connection_state() == ciplink::ConnectionState::Closed);
    });

    run("s7plus_batches_past_the_limit", [&] {
        ciplink::S7Plus plc(path);
        plc.open();
        std::vector<std::string> names;
        for (int i = 1; i <= 250; ++i) names.push_back("Line1.Items[" + std::to_string(i) + "]");
        auto r = plc.read(names);
        CHECK(r.size() == 250);
        CHECK(std::all_of(r.begin(), r.end(), [](const ciplink::Tag& t) { return bool(t); }));
    });
}

}  // namespace
