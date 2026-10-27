// ciplink.hpp - header-only C++17 RAII wrapper over the ciplink C ABI (ciplink.h).
// Documentation: https://rowanrama.github.io/ciplink/
//
//   ciplink::Logix plc("192.168.1.10/0");
//   plc.open();
//   ciplink::Tag t = plc.read_tag("Counter");
//   if (t) std::cout << t.value.as_int() << "\n";
//   plc.write_tag("Setpoint", 12.5);
//
// Connection and argument failures throw ciplink::Error; per-tag failures are returned in Tag::error.
// Values follow the C ABI's JSON forms (see ciplink.h): integers are int64_t (uint64_t above INT64_MAX),
// REAL/LREAL are double, raw bytes are ciplink::Bytes, arrays and structures nest.
#ifndef CIPLINK_HPP
#define CIPLINK_HPP

#include "ciplink.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace ciplink {

// ---------------------------------------------------------------------------------------------- errors

/// A failed call: the status code and the library's message.
class Error : public std::runtime_error {
public:
    Error(CiplinkStatus status, const std::string& message) : std::runtime_error(message), status_(status) {}
    CiplinkStatus status() const noexcept { return status_; }

private:
    CiplinkStatus status_;
};

namespace detail {

/// Owns a string returned by the library.
inline std::string take(char* s) {
    if (!s) return std::string();
    std::string out(s);
    ciplink_string_free(s);
    return out;
}

inline void check(CiplinkStatus st) {
    if (st != CIPLINK_STATUS_OK) {
        // the thread's error is always the one of this call, even when a handle is shared by threads
        throw Error(st, take(ciplink_last_error(nullptr)));
    }
}

}  // namespace detail

// ---------------------------------------------------------------------------------------------- values

struct Value;
/// Raw bytes (BYTE strings, generic message data).
struct Bytes {
    std::vector<uint8_t> data;
    bool operator==(const Bytes& o) const { return data == o.data; }
};
using Array = std::vector<Value>;
/// Structure members in order.
using Struct = std::vector<std::pair<std::string, Value>>;

/// A tag value; monostate is JSON null (no value).
struct Value {
    using Variant = std::variant<std::monostate, bool, int64_t, uint64_t, double, std::string, Bytes, Array, Struct>;
    Variant v;

    Value() = default;
    Value(bool b) : v(b) {}
    Value(int i) : v(int64_t(i)) {}
    Value(long i) : v(int64_t(i)) {}
    Value(long long i) : v(int64_t(i)) {}
    Value(unsigned i) : v(int64_t(i)) {}
    Value(unsigned long i) : v(unsigned_(i)) {}
    Value(unsigned long long i) : v(unsigned_(i)) {}
    Value(double d) : v(d) {}
    Value(float d) : v(double(d)) {}
    Value(const char* s) : v(std::string(s)) {}
    Value(std::string s) : v(std::move(s)) {}
    Value(Bytes b) : v(std::move(b)) {}
    Value(Array a) : v(std::move(a)) {}
    Value(Struct s) : v(std::move(s)) {}

    /// Unsigned numbers are int64_t when they fit, like parsed JSON, so equal values compare equal.
    static Variant unsigned_(unsigned long long u) {
        if (u <= uint64_t(std::numeric_limits<int64_t>::max())) return int64_t(u);
        return uint64_t(u);
    }

    bool is_null() const { return std::holds_alternative<std::monostate>(v); }
    template <class T> bool is() const { return std::holds_alternative<T>(v); }
    template <class T> const T& get() const { return std::get<T>(v); }

    bool as_bool() const { return get<bool>(); }
    /// An integer value (throws std::bad_variant_access for others, std::overflow_error above INT64_MAX).
    int64_t as_int() const {
        if (auto u = std::get_if<uint64_t>(&v)) {
            if (*u > uint64_t(std::numeric_limits<int64_t>::max())) throw std::overflow_error("value above INT64_MAX");
            return int64_t(*u);
        }
        return get<int64_t>();
    }
    uint64_t as_uint() const {
        if (auto i = std::get_if<int64_t>(&v)) return uint64_t(*i);
        return get<uint64_t>();
    }
    /// A number as double (integers convert).
    double as_double() const {
        if (auto i = std::get_if<int64_t>(&v)) return double(*i);
        if (auto u = std::get_if<uint64_t>(&v)) return double(*u);
        return get<double>();
    }
    const std::string& as_string() const { return get<std::string>(); }
    const Array& as_array() const { return get<Array>(); }
    const Struct& as_struct() const { return get<Struct>(); }
    /// A structure member or object key; throws std::out_of_range if missing.
    const Value& operator[](const std::string& key) const {
        for (auto& kv : as_struct())
            if (kv.first == key) return kv.second;
        throw std::out_of_range("no member " + key);
    }
    const Value& operator[](size_t i) const { return as_array().at(i); }

    bool operator==(const Value& o) const { return v == o.v; }
    bool operator!=(const Value& o) const { return !(v == o.v); }
};

// ---------------------------------------------------------------------------------------------- JSON

namespace detail {

inline void write_string(const std::string& s, std::string& out) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += char(c);
                }
        }
    }
    out += '"';
}

inline void write_json(const Value& value, std::string& out) {
    struct V {
        std::string& out;
        void operator()(std::monostate) { out += "null"; }
        void operator()(bool b) { out += b ? "true" : "false"; }
        void operator()(int64_t i) { out += std::to_string(i); }
        void operator()(uint64_t u) { out += std::to_string(u); }
        void operator()(double d) {
            if (std::isnan(d)) { out += "{\"$float\":\"NaN\"}"; return; }
            if (std::isinf(d)) { out += d > 0 ? "{\"$float\":\"Infinity\"}" : "{\"$float\":\"-Infinity\"}"; return; }
            char buf[32];
            std::snprintf(buf, sizeof buf, "%.17g", d);
            out += buf;
            if (!std::strpbrk(buf, ".eE")) out += ".0";
        }
        void operator()(const std::string& s) { write_string(s, out); }
        void operator()(const Bytes& b) {
            static const char* hex = "0123456789abcdef";
            out += "{\"$bytes\":\"";
            for (uint8_t c : b.data) { out += hex[c >> 4]; out += hex[c & 15]; }
            out += "\"}";
        }
        void operator()(const Array& a) {
            out += '[';
            for (size_t i = 0; i < a.size(); ++i) { if (i) out += ','; write_json(a[i], out); }
            out += ']';
        }
        void operator()(const Struct& s) {
            out += '{';
            for (size_t i = 0; i < s.size(); ++i) {
                if (i) out += ',';
                write_string(s[i].first, out);
                out += ':';
                write_json(s[i].second, out);
            }
            out += '}';
        }
    };
    std::visit(V{out}, value.v);
}

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    Value parse() {
        Value v = value();
        ws();
        if (i_ != s_.size()) fail();
        return v;
    }

private:
    const std::string& s_;
    size_t i_ = 0;

    [[noreturn]] void fail() const { throw std::runtime_error("ciplink: bad JSON at offset " + std::to_string(i_)); }
    void ws() { while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\n' || s_[i_] == '\r' || s_[i_] == '\t')) ++i_; }
    char peek() { ws(); if (i_ >= s_.size()) fail(); return s_[i_]; }
    void expect(char c) { if (peek() != c) fail(); ++i_; }
    bool literal(const char* w) {
        size_t n = std::strlen(w);
        if (s_.compare(i_, n, w) == 0) { i_ += n; return true; }
        return false;
    }

    Value value() {
        char c = peek();
        if (c == '{') return object();
        if (c == '[') {
            ++i_;
            Array a;
            if (peek() == ']') { ++i_; return a; }
            for (;;) {
                a.push_back(value());
                if (peek() == ',') { ++i_; continue; }
                expect(']');
                return a;
            }
        }
        if (c == '"') return string();
        if (literal("true")) return true;
        if (literal("false")) return false;
        if (literal("null")) return Value();
        return number();
    }

    Value object() {
        expect('{');
        Struct s;
        if (peek() == '}') { ++i_; return s; }
        for (;;) {
            if (peek() != '"') fail();
            std::string k = string();
            expect(':');
            s.emplace_back(std::move(k), value());
            if (peek() == ',') { ++i_; continue; }
            expect('}');
            break;
        }
        if (s.size() == 1 && s[0].second.is<std::string>()) {
            const std::string& t = s[0].second.as_string();
            if (s[0].first == "$bytes") {
                Bytes b;
                if (t.size() % 2) fail();
                for (size_t j = 0; j < t.size(); j += 2) b.data.push_back(uint8_t(std::stoul(t.substr(j, 2), nullptr, 16)));
                return b;
            }
            if (s[0].first == "$float") {
                if (t == "NaN") return std::numeric_limits<double>::quiet_NaN();
                if (t == "Infinity") return std::numeric_limits<double>::infinity();
                if (t == "-Infinity") return -std::numeric_limits<double>::infinity();
            }
        }
        return s;
    }

    static void utf8(uint32_t cp, std::string& out) {
        if (cp < 0x80) out += char(cp);
        else if (cp < 0x800) { out += char(0xc0 | (cp >> 6)); out += char(0x80 | (cp & 0x3f)); }
        else if (cp < 0x10000) { out += char(0xe0 | (cp >> 12)); out += char(0x80 | ((cp >> 6) & 0x3f)); out += char(0x80 | (cp & 0x3f)); }
        else { out += char(0xf0 | (cp >> 18)); out += char(0x80 | ((cp >> 12) & 0x3f)); out += char(0x80 | ((cp >> 6) & 0x3f)); out += char(0x80 | (cp & 0x3f)); }
    }

    uint32_t hex4() {
        if (i_ + 4 > s_.size()) fail();
        uint32_t cp = uint32_t(std::stoul(s_.substr(i_, 4), nullptr, 16));
        i_ += 4;
        return cp;
    }

    std::string string() {
        expect('"');
        std::string out;
        while (i_ < s_.size() && s_[i_] != '"') {
            char c = s_[i_++];
            if (c != '\\') { out += c; continue; }
            if (i_ >= s_.size()) fail();
            char e = s_[i_++];
            switch (e) {
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'u': {
                    uint32_t cp = hex4();
                    if (cp >= 0xd800 && cp < 0xdc00 && literal("\\u")) cp = 0x10000 + ((cp - 0xd800) << 10) + (hex4() - 0xdc00);
                    utf8(cp, out);
                    break;
                }
                default: out += e;
            }
        }
        if (i_ >= s_.size()) fail();
        ++i_;
        return out;
    }

    Value number() {
        size_t start = i_;
        bool is_float = false;
        while (i_ < s_.size() && std::strchr("+-0123456789.eE", s_[i_])) {
            if (std::strchr(".eE", s_[i_])) is_float = true;
            ++i_;
        }
        if (start == i_) fail();
        std::string t = s_.substr(start, i_ - start);
        if (is_float) return std::strtod(t.c_str(), nullptr);
        if (t[0] == '-') return int64_t(std::strtoll(t.c_str(), nullptr, 10));
        uint64_t u = std::strtoull(t.c_str(), nullptr, 10);
        if (u <= uint64_t(std::numeric_limits<int64_t>::max())) return int64_t(u);
        return u;
    }
};

}  // namespace detail

/// A value as the C ABI's JSON.
inline std::string to_json(const Value& v) {
    std::string out;
    detail::write_json(v, out);
    return out;
}

/// The C ABI's JSON as a value (objects become Struct).
inline Value parse_json(const std::string& text) { return detail::Parser(text).parse(); }

// ---------------------------------------------------------------------------------------------- results

/// A per-tag failure.
struct TagError {
    std::string message;
    /// not_found, bad_value, bad_request, access, refused, table_changed, comm, device or other.
    std::string kind;
    std::optional<int> status;
    std::optional<int> ext;
};

/// The result of reading or writing one tag, or of a generic message.
struct Tag {
    std::string tag;
    Value value;
    std::optional<std::string> type;
    std::optional<TagError> error;

    /// True if there is a value and no error.
    explicit operator bool() const { return !value.is_null() && !error; }

    static Tag from(const Value& j) {
        Tag t;
        t.tag = j["tag"].as_string();
        t.value = j["value"];
        if (!j["type"].is_null()) t.type = j["type"].as_string();
        const Value& e = j["error"];
        if (!e.is_null()) {
            TagError err;
            err.message = e["message"].as_string();
            err.kind = e["kind"].as_string();
            if (!e["status"].is_null()) err.status = int(e["status"].as_int());
            if (!e["ext"].is_null()) err.ext = int(e["ext"].as_int());
            t.error = std::move(err);
        }
        return t;
    }
};

/// A generic CIP message.
struct Message {
    uint8_t service = 0;
    uint32_t class_code = 0;
    uint32_t instance = 0;
    std::optional<uint32_t> attribute;
    std::vector<uint8_t> request_data;
    bool connected = true;
    bool unconnected_send = false;
    /// Route of the Unconnected Send: nullopt for the driver's path, "" for none, else e.g. "bp/2".
    std::optional<std::string> route_path;
    std::string name = "generic";
};

// ---------------------------------------------------------------------------------------------- drivers

/// Common driver operations; owns the handle (movable, not copyable). Thread-safe.
class Driver {
public:
    Driver(Driver&&) noexcept = default;
    Driver& operator=(Driver&&) noexcept = default;
    virtual ~Driver() = default;

    void open() { detail::check(ciplink_open(h())); }
    void close() { detail::check(ciplink_close(h())); }
    bool connected() const { return ciplink_connected(h()); }

    /// Sends a generic message; the reply data is the value as Bytes (null if none).
    Tag generic_message(const Message& m) {
        CiplinkMessage c{};
        c.service = m.service;
        c.class_code = m.class_code;
        c.instance = m.instance;
        c.attribute = m.attribute ? int32_t(*m.attribute) : -1;
        c.request_data = m.request_data.data();
        c.request_data_len = m.request_data.size();
        c.connected = m.connected;
        c.unconnected_send = m.unconnected_send;
        c.route_path = m.route_path ? m.route_path->c_str() : nullptr;
        c.name = m.name.c_str();
        char* out = nullptr;
        detail::check(ciplink_generic_message(h(), &c, &out));
        return Tag::from(parse_json(detail::take(out)));
    }

    /// Sends a raw connected CIP message (service, request path, data; no sequence count) over the current CIP
    /// connection and returns the raw reply frame. Does not make the Forward Open (a Logix open() does).
    std::vector<uint8_t> send_connected(const std::vector<uint8_t>& message) {
        return raw_(ciplink_send_connected, message);
    }
    /// Sends a raw unconnected CIP message (SendRRData) and returns the raw reply frame.
    std::vector<uint8_t> send_unconnected(const std::vector<uint8_t>& message) {
        return raw_(ciplink_send_unconnected, message);
    }

    /// The connection size of the next Forward Open.
    uint16_t connection_size() const {
        uint16_t size = 0;
        detail::check(ciplink_connection_size(h(), &size));
        return size;
    }
    /// Sets the connection size (1 to 65535); throws while the CIP connection is open (close first).
    void set_connection_size(uint16_t size) { detail::check(ciplink_set_connection_size(h(), size)); }
    /// The socket timeout in seconds, nullopt if the socket blocks forever.
    std::optional<double> socket_timeout() const {
        double s = 0;
        detail::check(ciplink_socket_timeout(h(), &s));
        if (s < 0) return std::nullopt;
        return s;
    }
    /// Sets the socket timeout (positive seconds, nullopt to block forever); applies to an open connection too.
    void set_socket_timeout(std::optional<double> seconds) {
        detail::check(ciplink_set_socket_timeout(h(), seconds ? *seconds : -1.0));
    }

    /// The identity of the module in backplane `slot` (product_name, serial, ...).
    Value get_module_info(int64_t slot) {
        return parse_json(json_call([&](char** o) { return ciplink_get_module_info(h(), slot, o); }));
    }

    // Device browsing like RSWho. A route is relative to the device at the driver's IP address: "" is that device,
    // "bp/3" the module in slot 3 of its backplane, "bp/2/enet/192.168.1.10" a device behind the module in slot 2.

    /// The identity of the device at `route` (product_name, serial, ...).
    Value get_identity(const std::string& route = "") {
        return parse_json(json_call([&](char** o) { return ciplink_get_identity(h(), route.c_str(), o); }));
    }
    /// What the ciplink device at `route` runs (name, version, detail, summary, ciplink_version, assemblies,
    /// connections), null for any other device. `summary` is the line a device browser shows.
    Value get_app(const std::string& route = "") {
        return parse_json(json_call([&](char** o) { return ciplink_get_app(h(), route.c_str(), o); }));
    }
    /// The ports of the device at `route`: an array of {number, type, type_name, name, address, ip, netmask,
    /// nodes}; `nodes` are the addresses browse_port probes (the slots, or every host of an EtherNet/IP port's
    /// subnet, at most a /24).
    Value get_ports(const std::string& route = "") {
        return parse_json(json_call([&](char** o) { return ciplink_get_ports(h(), route.c_str(), o); }));
    }
    /// Probes every address on `port` of the device at `route` (`nodes`, by default the port's own) from `workers`
    /// connections at once: an array of {route, address, identity (null if nothing answered), error}, in address
    /// order. Each missing device may cost the bridge's ~4 s timeout.
    Value browse_port(const std::string& route, uint16_t port,
                      const std::optional<std::vector<std::string>>& nodes = std::nullopt, size_t workers = 16) {
        std::string list = nodes_json(nodes);
        return parse_json(json_call([&](char** o) {
            return ciplink_browse_port(h(), route.c_str(), port, nodes ? list.c_str() : nullptr, workers, o);
        }));
    }
    /// browse_port, calling `found` on this thread with each node as it answers (in any order) until it returns
    /// false. An exception thrown by `found` stops the scan and is rethrown.
    void scan_port(const std::string& route, uint16_t port, const std::function<bool(const Value&)>& found,
                   const std::optional<std::vector<std::string>>& nodes = std::nullopt, size_t workers = 16) {
        struct Call {
            const std::function<bool(const Value&)>& found;
            std::exception_ptr error;
        } call{found, nullptr};
        auto trampoline = [](void* user, const char* node) -> bool {
            auto c = static_cast<Call*>(user);
            try {
                return c->found(parse_json(node));
            } catch (...) {
                c->error = std::current_exception();
                return false;
            }
        };
        std::string list = nodes_json(nodes);
        detail::check(ciplink_scan_port(h(), route.c_str(), port, nodes ? list.c_str() : nullptr, workers,
                                        trampoline, &call));
        if (call.error) std::rethrow_exception(call.error);
    }

    /// The raw handle for calls this wrapper does not cover.
    CiplinkDriver* handle() const { return h(); }

protected:
    using New = CiplinkStatus (*)(const char*, const char*, CiplinkDriver**);
    Driver(New make, const std::string& path, const std::string& options_json) {
        CiplinkDriver* raw = nullptr;
        detail::check(make(path.c_str(), options_json.empty() ? nullptr : options_json.c_str(), &raw));
        handle_.reset(raw);
    }

    CiplinkDriver* h() const { return handle_.get(); }

    std::vector<Tag> read_(const std::vector<std::string>& tags) {
        std::vector<const char*> ptrs;
        ptrs.reserve(tags.size());
        for (auto& t : tags) ptrs.push_back(t.c_str());
        char* out = nullptr;
        detail::check(ciplink_read(h(), ptrs.data(), ptrs.size(), &out));
        return results(detail::take(out));
    }

    std::vector<Tag> write_(const std::vector<std::pair<std::string, Value>>& items) {
        std::string json = "[";
        for (size_t i = 0; i < items.size(); ++i) {
            if (i) json += ',';
            json += '[';
            detail::write_string(items[i].first, json);
            json += ',';
            detail::write_json(items[i].second, json);
            json += ']';
        }
        json += ']';
        char* out = nullptr;
        detail::check(ciplink_write(h(), json.c_str(), &out));
        return results(detail::take(out));
    }

    using RawSend = CiplinkStatus (*)(const CiplinkDriver*, const uint8_t*, size_t, uint8_t**, size_t*);
    std::vector<uint8_t> raw_(RawSend send, const std::vector<uint8_t>& message) {
        uint8_t* data = nullptr;
        size_t len = 0;
        detail::check(send(h(), message.data(), message.size(), &data, &len));
        std::vector<uint8_t> out(data, data + len);
        ciplink_bytes_free(data, len);
        return out;
    }

    static std::vector<Tag> results(const std::string& json) {
        std::vector<Tag> tags;
        Value parsed = parse_json(json);
        for (auto& j : parsed.as_array()) tags.push_back(Tag::from(j));
        return tags;
    }

    static std::string nodes_json(const std::optional<std::vector<std::string>>& nodes) {
        std::string json = "[";
        if (nodes)
            for (size_t i = 0; i < nodes->size(); ++i) {
                if (i) json += ',';
                detail::write_string((*nodes)[i], json);
            }
        return json + "]";
    }

    /// Runs `f(&out)` and returns the JSON it produced.
    template <class F>
    static std::string json_call(F f) {
        char* out = nullptr;
        detail::check(f(&out));
        return detail::take(out);
    }

private:
    struct Free {
        void operator()(CiplinkDriver* p) const noexcept { ciplink_driver_free(p); }
    };
    std::unique_ptr<CiplinkDriver, Free> handle_;
};

// ---------------------------------------------------------------------------------------------- trends

/// One sample of every pen of a trend.
struct TrendSample {
    /// Controller time of the sample, microseconds since 1970 UTC.
    uint64_t timestamp_us = 0;
    /// Time since the trend started, microseconds.
    uint64_t elapsed_us = 0;
    /// One value per pen, in pen order.
    std::vector<Value> values;
};

/// A pen of a trend: the tag and the type sampled ("BOOL" for a bit).
struct TrendPen {
    std::string tag;
    std::string type;
};

/// A running controller-side trend, from Logix::trend (movable, not copyable). Destroying it stops the trend
/// without waiting; close() waits for the cleanup.
class Trend {
public:
    Trend(Trend&&) noexcept = default;
    Trend& operator=(Trend&&) noexcept = default;

    /// The samples uploaded since the last read, oldest first; throws the trend's error once it failed and
    /// every sample was taken.
    std::vector<TrendSample> read() {
        char* out = nullptr;
        detail::check(ciplink_trend_read(h(), &out));
        std::vector<TrendSample> samples;
        Value parsed = parse_json(detail::take(out));
        for (auto& j : parsed.as_array()) {
            samples.push_back({j["timestamp_us"].as_uint(), j["elapsed_us"].as_uint(), j["values"].as_array()});
        }
        return samples;
    }

    /// Stops the trend and waits for its cleanup; throws the trend's error if it failed.
    void close() { detail::check(ciplink_trend_close(h())); }

    std::vector<TrendPen> pens() const {
        std::vector<TrendPen> pens;
        Value state = info();
        for (auto& p : state["pens"].as_array()) pens.push_back({p["tag"].as_string(), p["type"].as_string()});
        return pens;
    }
    uint64_t start_time_us() const { return info()["start_time_us"].as_uint(); }
    /// True until the trend is closed, its duration is over, or it failed.
    bool running() const { return info()["running"].as_bool(); }
    /// Samples uploaded so far, including dropped ones.
    uint64_t received() const { return info()["received"].as_uint(); }
    /// Samples dropped because `capacity` samples were waiting to be read.
    uint64_t dropped() const { return info()["dropped"].as_uint(); }
    /// Why the trend failed, if it did.
    std::optional<std::string> error() const {
        Value e = info()["error"];
        return e.is_null() ? std::nullopt : std::optional<std::string>(e.as_string());
    }

    /// The raw handle for calls this wrapper does not cover.
    CiplinkTrend* handle() const { return h(); }

private:
    friend class Logix;
    explicit Trend(CiplinkTrend* raw) : handle_(raw) {}

    CiplinkTrend* h() const { return handle_.get(); }

    Value info() const {
        char* out = nullptr;
        detail::check(ciplink_trend_info(h(), &out));
        return parse_json(detail::take(out));
    }

    struct Free {
        void operator()(CiplinkTrend* p) const noexcept { ciplink_trend_free(p); }
    };
    std::unique_ptr<CiplinkTrend, Free> handle_;
};

/// A ControlLogix / CompactLogix / Micro800 driver.
class Logix : public Driver {
public:
    /// `path` like "192.168.1.10", "192.168.1.10/2" or a CIP route; `options_json` see ciplink_logix_new.
    explicit Logix(const std::string& path, const std::string& options_json = "")
        : Driver(ciplink_logix_new, path, options_json) {}

    std::vector<Tag> read(const std::vector<std::string>& tags) { return read_(tags); }
    /// One tag (a separate name, as a braced list of strings would be ambiguous with read(vector)).
    Tag read_tag(const std::string& tag) { return read_({tag}).at(0); }
    std::vector<Tag> write(const std::vector<std::pair<std::string, Value>>& items) { return write_(items); }
    Tag write_tag(const std::string& tag, const Value& value) { return write_({{tag, value}}).at(0); }

    /// Starts a controller-side trend: the controller samples `tags` (atomic tags, members or elements of up to
    /// 32 bits, or bits such as "Tag.3") every `period_ms` and the trend uploads them on a connection of its own.
    /// `capacity` samples are kept until read (the oldest are dropped); `duration` seconds stops it by itself.
    Trend trend(const std::vector<std::string>& tags, double period_ms = 10, size_t capacity = 4096,
                std::optional<double> duration = std::nullopt) {
        std::vector<const char*> ptrs;
        ptrs.reserve(tags.size());
        for (auto& t : tags) ptrs.push_back(t.c_str());
        std::string options = "{\"period_ms\":" + std::to_string(period_ms) +
                              ",\"capacity\":" + std::to_string(capacity) +
                              ",\"duration\":" + (duration ? std::to_string(*duration) : "null") + "}";
        CiplinkTrend* raw = nullptr;
        detail::check(ciplink_trend_start(h(), ptrs.data(), ptrs.size(), options.c_str(), &raw));
        return Trend(raw);
    }

    /// Tag definitions, data types, controller info and tag list as JSON text (the Python driver's dicts).
    std::string tags_json() { return json_call([&](char** o) { return ciplink_tags(h(), o); }); }
    std::string data_types_json() { return json_call([&](char** o) { return ciplink_data_types(h(), o); }); }
    std::string info_json() { return json_call([&](char** o) { return ciplink_info(h(), o); }); }
    std::string tag_info_json(const std::string& tag) {
        return json_call([&](char** o) { return ciplink_tag_info(h(), tag.c_str(), o); });
    }
    /// Uploads the tag list: nullopt for controller tags, "*" for all, else a program name. With `cache` it
    /// replaces tags_json(); `tag_namespace_filter` keeps only names (without "Program:X.") starting with it.
    std::string tag_list_json(const std::optional<std::string>& program = std::nullopt, bool cache = true,
                              const std::string& tag_namespace_filter = "") {
        return json_call([&](char** o) {
            return ciplink_tag_list(h(), program ? program->c_str() : nullptr, cache, tag_namespace_filter.c_str(), o);
        });
    }

    /// The PLC clock in microseconds since 1970 UTC; throws ciplink::Error on a failed reply.
    uint64_t get_plc_time() {
        Tag t = Tag::from(parse_json(json_call([&](char** o) { return ciplink_get_plc_time(h(), o); })));
        if (t.error) throw Error(CIPLINK_STATUS_RESPONSE, t.error->message);
        return t.value["microseconds"].as_uint();
    }
    /// Sets the PLC clock (microseconds since 1970 UTC, nullopt for this computer's clock).
    Tag set_plc_time(std::optional<uint64_t> microseconds = std::nullopt) {
        int64_t us = microseconds ? int64_t(*microseconds) : -1;
        return Tag::from(parse_json(json_call([&](char** o) { return ciplink_set_plc_time(h(), us, o); })));
    }

    /// Reads the controller program name.
    std::string get_plc_name() {
        return parse_json(json_call([&](char** o) { return ciplink_get_plc_name(h(), o); })).as_string();
    }
    /// Reads the controller identity plus "keyswitch".
    Value get_plc_info() { return parse_json(json_call([&](char** o) { return ciplink_get_plc_info(h(), o); })); }
    /// Reloads the tag list if the controller's tag table changed; true if it did.
    bool check_tag_table() {
        bool changed = false;
        detail::check(ciplink_check_tag_table(h(), &changed));
        return changed;
    }
    /// The tag table version the tags were loaded at (5 numbers), or null if unknown.
    Value tag_table_version() {
        return parse_json(json_call([&](char** o) { return ciplink_tag_table_version(h(), o); }));
    }
    /// Authenticates this connection for metadata (Description) reads with the bundled credentials.
    Tag authenticate_metadata() {
        return Tag::from(parse_json(json_call(
            [&](char** o) { return ciplink_authenticate_metadata(h(), nullptr, 0, nullptr, 0, o); })));
    }
    /// The same with caller-supplied credentials: the signed certificate and its unencrypted PKCS #1 or
    /// PKCS #8 DER private key. Credentials that do not parse or match throw ciplink::Error (Request).
    Tag authenticate_metadata(const std::vector<uint8_t>& certificate, const std::vector<uint8_t>& private_key_der) {
        // a non-NULL pointer even for an empty vector, so empty input is "bad credentials", not "bundled"
        static const uint8_t none = 0;
        const uint8_t* c = certificate.empty() ? &none : certificate.data();
        const uint8_t* k = private_key_der.empty() ? &none : private_key_der.data();
        return Tag::from(parse_json(json_call([&](char** o) {
            return ciplink_authenticate_metadata(h(), c, certificate.size(), k, private_key_der.size(), o);
        })));
    }
    /// Descriptions of `tags` (value is the text); `language` 0x7F is the project default.
    std::vector<Tag> get_tag_descriptions(const std::vector<std::string>& tags, uint16_t language = 0x7F,
                                          const std::string& encoding = "utf-8") {
        std::vector<const char*> ptrs;
        ptrs.reserve(tags.size());
        for (auto& t : tags) ptrs.push_back(t.c_str());
        return results(json_call([&](char** o) {
            return ciplink_get_tag_descriptions(h(), ptrs.data(), ptrs.size(), language, encoding.c_str(), o);
        }));
    }
    Tag get_tag_description(const std::string& tag, uint16_t language = 0x7F,
                            const std::string& encoding = "utf-8") {
        return get_tag_descriptions({tag}, language, encoding).at(0);
    }
};

/// An SLC 500 / MicroLogix driver (data file addresses such as "N7:0" or "N7:0{3}").
class Slc : public Driver {
public:
    explicit Slc(const std::string& path, const std::string& options_json = "")
        : Driver(ciplink_slc_new, path, options_json) {}

    std::vector<Tag> read(const std::vector<std::string>& addresses) { return read_(addresses); }
    Tag read_tag(const std::string& address) { return read_({address}).at(0); }
    std::vector<Tag> write(const std::vector<std::pair<std::string, Value>>& items) { return write_(items); }
    Tag write_tag(const std::string& address, const Value& value) { return write_({{address, value}}).at(0); }

    /// The processor type, e.g. "1747-L552", or null if unknown.
    Value get_processor_type() {
        return parse_json(json_call([&](char** o) { return ciplink_slc_processor_type(h(), o); }));
    }
    /// The data file directory: {"N7": {"elements": n, "length": bytes}, ...}.
    Value get_file_directory() {
        return parse_json(json_call([&](char** o) { return ciplink_slc_file_directory(h(), o); }));
    }
    /// `num_data_logs` records of data log queue `queue_num` (null entries where none was read).
    Value get_datalog_queue(size_t num_data_logs, uint8_t queue_num) {
        return parse_json(
            json_call([&](char** o) { return ciplink_slc_datalog_queue(h(), num_data_logs, queue_num, o); }));
    }
};

/// A plain CIP driver: generic messages only.
class Cip : public Driver {
public:
    explicit Cip(const std::string& path, const std::string& options_json = "")
        : Driver(ciplink_cip_new, path, options_json) {}
};

/// The ListIdentity reply of the device at `path`, or null if it refused.
inline Value list_identity(const std::string& path) {
    char* o = nullptr;
    detail::check(ciplink_list_identity(path.c_str(), &o));
    return parse_json(detail::take(o));
}

/// Devices answering a ListIdentity broadcast (takes a few seconds).
inline Value discover(const std::string& broadcast = "255.255.255.255") {
    char* o = nullptr;
    detail::check(ciplink_discover(broadcast.c_str(), &o));
    return parse_json(detail::take(o));
}

// ---------------------------------------------------------------------------------------------- tag server

/// A tag server (see `ciplink-server`) running in this process on threads of its own (movable, not copyable).
/// Destroying it stops it; stop() does the same and throws if the shutdown failed.
class Server {
public:
    /// Starts the server of a config file (the TOML file of `ciplink-server run --config`) and returns once it
    /// listens. `mock` serves simulated values from each PLC's mock_tags file; `host` and `port` override the
    /// config's (port 0 picks a free port).
    explicit Server(const std::string& config_path, bool mock = false, std::optional<std::string> host = std::nullopt,
                    std::optional<uint16_t> port = std::nullopt) {
        Struct options{{"mock", Value(mock)}};
        if (host) options.emplace_back("host", Value(*host));
        if (port) options.emplace_back("port", Value(int64_t(*port)));
        CiplinkServer* raw = nullptr;
        detail::check(ciplink_server_start(config_path.c_str(), to_json(Value(options)).c_str(), &raw));
        handle_.reset(raw);
    }
    Server(Server&&) noexcept = default;
    Server& operator=(Server&&) noexcept = default;

    /// The address it listens on, e.g. "127.0.0.1:8765".
    std::string address() const {
        char* out = nullptr;
        detail::check(ciplink_server_address(handle_.get(), &out));
        return detail::take(out);
    }

    /// Stops the server: pressed buttons are released, the PLC connections closed, the audit log flushed.
    void stop() { detail::check(ciplink_server_stop(handle_.release())); }

private:
    struct Stop {
        void operator()(CiplinkServer* p) const noexcept { ciplink_server_stop(p); }
    };
    std::unique_ptr<CiplinkServer, Stop> handle_;
};

inline std::string version() { return ciplink_version(); }

}  // namespace ciplink

#endif  // CIPLINK_HPP
