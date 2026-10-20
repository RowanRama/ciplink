// Reads and writes a few tags: example <path>, e.g. example 127.0.0.1:44818 against the simulator.
#include "ciplink.hpp"

#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: example <path>\n";
        return 2;
    }
    try {
        ciplink::Logix plc(argv[1], R"({"socket_timeout": 5})");
        plc.open();
        for (const ciplink::Tag& t : plc.read({"dint1", "real1", "str1", "udt1"})) {
            if (t)
                std::cout << t.tag << " (" << t.type.value_or("?") << ") = " << ciplink::to_json(t.value) << "\n";
            else
                std::cout << t.tag << " failed: " << t.error->message << "\n";
        }
        ciplink::Tag w = plc.write_tag("dint1", 42);
        std::cout << "write dint1: " << (w ? "ok" : w.error->message) << "\n";
        plc.close();
    } catch (const ciplink::Error& e) {
        std::cerr << "error " << int(e.status()) << ": " << e.what() << "\n";
        return 1;
    }
    return 0;
}
