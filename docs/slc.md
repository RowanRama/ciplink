# SLC 500 and MicroLogix

The SLC driver reads and writes data file addresses over PCCC. It uses a standard Forward Open with a 500-byte
connection by default.

## Addresses

| Address | Means |
|---|---|
| `N7:0` | integer file 7, element 0 (also `F` float, `L` long, `B` bit file, `S` status, `A` ASCII, `ST` string) |
| `N7:0{5}` | 5 elements from `N7:0` |
| `N7:0/3` | bit 3 of `N7:0` |
| `B3/20` | bit 20 of bit file 3 |
| `T4:0.ACC` | a timer or counter member: `ACC`, `PRE`, `EN`, `DN`, `TT` (timers), `CU`, `CD`, `OV`, `UN`, `UA` (counters) |
| `I:0/1`, `O:0.1/2` | input and output image bits and words |

=== "Python"

    ```python
    from ciplink import SLCDriver

    with SLCDriver("192.0.2.20") as plc:
        print(plc.get_processor_type())          # e.g. '1747-L552'
        print(plc.read("N7:0{5}"))               # Tag(tag='N7:0', value=[10, 20, 30, 40, 50], ...)
        plc.write(("N7:0", 25), ("F8:0", 1.5), ("B3/2", True))
        print(plc.get_file_directory())          # {'N7': {'elements': 100, 'length': 200}, ...}
    ```

=== "Rust"

    ```rust
    use ciplink::slc::driver::SlcDriver;
    use ciplink::Value;

    let plc = SlcDriver::new("192.0.2.20", SlcDriver::default_options())?;
    plc.open()?;
    println!("{:?}", plc.get_processor_type()?);
    for tag in plc.read(&["N7:0{5}", "T4:0.ACC"])? {
        println!("{} = {:?}", tag.tag, tag.value);
    }
    plc.write(&[("N7:0", Value::Int(25)), ("F8:0", Value::Real(1.5)), ("B3/2", Value::Bool(true))])?;
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new SlcDriver("192.0.2.20");
    plc.Open();
    Console.WriteLine(plc.GetProcessorType());
    foreach (Tag tag in plc.Read("N7:0{5}", "T4:0.ACC"))
        Console.WriteLine($"{tag.Name} = {tag.Value}");
    plc.Write(("N7:0", 25), ("F8:0", 1.5), ("B3/2", true));
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Slc plc("192.0.2.20");
    plc.open();
    std::cout << ciplink::to_json(plc.get_processor_type()) << "\n";
    for (const ciplink::Tag& tag : plc.read({"N7:0{5}", "T4:0.ACC"}))
        std::cout << tag.tag << " = " << ciplink::to_json(tag.value) << "\n";
    plc.write({{"N7:0", 25}, {"F8:0", 1.5}, {"B3/2", true}});
    ```

=== "C"

    ```c
    #include <stdio.h>
    #include "ciplink.h"

    CiplinkDriver *plc = NULL;
    ciplink_slc_new("192.0.2.20", NULL, &plc);
    if (ciplink_open(plc) == CIPLINK_STATUS_OK) {
        const char *addresses[] = {"N7:0{5}", "T4:0.ACC"};
        char *json = NULL;
        if (ciplink_read(plc, addresses, 2, &json) == CIPLINK_STATUS_OK) {
            printf("%s\n", json);
            ciplink_string_free(json);
        }
        if (ciplink_write(plc, "[[\"N7:0\", 25], [\"F8:0\", 1.5], [\"B3/2\", true]]", &json) == CIPLINK_STATUS_OK)
            ciplink_string_free(json);
    }
    ciplink_driver_free(plc);
    ```

`get_datalog_queue(count, queue)` reads `count` records of a data log queue (and one more to clear it).
