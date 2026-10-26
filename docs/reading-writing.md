# Reading and writing tags

The Logix driver reads and writes any tag by name: atomic tags, arrays, strings, whole UDTs and AOIs, members,
elements and bits. It packs as many tags as fit into each request (Multiple Service Packet), splits values too large
for one packet into fragments, and checks every reply against the controller's tag table version. You never need
separate calls for strings, arrays or large tags.

## Tag names

| Name | Means |
|---|---|
| `Counter` | a controller-scoped tag |
| `Program:MainProgram.Step` | a program-scoped tag |
| `Tank.Level` | a member of a UDT or AOI (nest as deep as needed: `Line.Tanks[2].Level`) |
| `Recipe[3]` | one array element; `Grid[1,2]` in a two-dimensional array |
| `Recipe{10}` | 10 elements from the start of the array |
| `Recipe[20]{3}` | 3 elements starting at index 20 |
| `Counter.5` | bit 5 of an integer (read as a BOOL, written with a read-modify-write) |
| `Flags[40]` | one element of a BOOL array |

Without an index an array tag means its first element (`Recipe` is `Recipe[0]{1}`). The `{n}` count is the total
number of elements, counted across all dimensions of a multi-dimensional array in row-major order: in a `DINT[3,2]`,
`Grid[1,1]{3}` is `[1,1]`, `[2,0]` and `[2,1]`.

## Read

=== "Python"

    ```python
    from ciplink import LogixDriver

    with LogixDriver("192.0.2.10") as plc:
        counter = plc.read("Counter")            # one tag: one Tag
        print(counter.value)                     # 42
        level, recipe, tank = plc.read("Tank.Level", "Recipe{10}", "Tank")   # several: a list
        print(recipe.value)                      # [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        print(tank.value)                        # {'Level': 50.0, 'Setpoint': 75.5}
    ```

=== "Rust"

    ```rust
    use ciplink::logix::driver::{LogixDriver, LogixOptions};
    use ciplink::Value;

    let plc = LogixDriver::new("192.0.2.10", LogixOptions::default())?;
    plc.open()?;
    let results = plc.read(&["Counter", "Recipe{10}", "Tank"])?;
    if let Some(Value::DInt(counter)) = results[0].value {
        println!("Counter = {counter}");
    }
    if let Some(Value::Array(recipe)) = &results[1].value {
        println!("{} recipe steps", recipe.len());
    }
    if let Some(Value::Struct(tank)) = &results[2].value {
        println!("Tank.Level = {:?}", tank["Level"]);
    }
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new LogixDriver("192.0.2.10");
    plc.Open();
    long counter = (long)plc.Read("Counter").Value!;            // integers are long
    var recipe = (object?[])plc.Read("Recipe{10}").Value!;      // arrays are object?[]
    var tank = (Dictionary<string, object?>)plc.Read("Tank").Value!;   // structures are dictionaries
    Console.WriteLine($"{counter}, {recipe.Length} steps, level {tank["Level"]}");
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Logix plc("192.0.2.10");
    plc.open();
    int64_t counter = plc.read_tag("Counter").value.as_int();
    std::vector<ciplink::Tag> tags = plc.read({"Recipe{10}", "Tank"});
    const ciplink::Array& recipe = tags[0].value.as_array();
    double level = tags[1].value["Level"].as_double();
    std::cout << counter << ", " << recipe.size() << " steps, level " << level << "\n";
    ```

=== "C"

    ```c
    #include <stdio.h>
    #include "ciplink.h"

    CiplinkDriver *plc = NULL;
    ciplink_logix_new("192.0.2.10", NULL, &plc);
    if (ciplink_open(plc) == CIPLINK_STATUS_OK) {
        const char *tags[] = {"Counter", "Recipe{10}", "Tank"};
        char *json = NULL;
        if (ciplink_read(plc, tags, 3, &json) == CIPLINK_STATUS_OK) {
            /* [{"tag":"Counter","value":42,"type":"DINT","error":null},
                {"tag":"Recipe{10}","value":[1,2,...],"type":"DINT[10]","error":null},
                {"tag":"Tank","value":{"Level":50.0,"Setpoint":75.5},"type":"TankData","error":null}] */
            printf("%s\n", json);
            ciplink_string_free(json);
        }
    }
    ciplink_driver_free(plc);
    ```

    Parse the JSON with the library of your choice. [Values and results](values.md) has the format.

A whole structure can be read as long as none of its members has External Access *None*.

## Write

Write a tag and its value, or several pairs at once. Integers and floats are range-checked against the tag's type
before anything is sent. An array write takes a list of values; a structure write takes a map of member names, nested
as needed (avoid writing whole built-in structures such as `TIMER` or `PID`).

=== "Python"

    ```python
    plc.write("Counter", 0)                                       # one tag
    plc.write(("Tank.Setpoint", 75.5), ("Motor.Start", True))     # several: (tag, value) pairs
    plc.write("Recipe{5}", [10, 20, 30, 40, 50])                  # array elements
    plc.write("Tank", {"Level": 0.0, "Setpoint": 60.0})           # a whole UDT
    plc.write("Message", "Line 2 running")                        # a STRING
    ```

=== "Rust"

    ```rust
    use ciplink::Value;
    use indexmap::IndexMap;

    plc.write(&[("Counter", Value::DInt(0))])?;
    plc.write(&[("Tank.Setpoint", Value::Real(75.5)), ("Motor.Start", Value::Bool(true))])?;
    let steps = [10, 20, 30, 40, 50].into_iter().map(Value::DInt).collect();
    plc.write(&[("Recipe{5}", Value::Array(steps))])?;
    let tank = IndexMap::from([("Level".to_string(), Value::Real(0.0)), ("Setpoint".to_string(), Value::Real(60.0))]);
    plc.write(&[("Tank", Value::Struct(tank))])?;
    plc.write(&[("Message", Value::String("Line 2 running".into()))])?;
    ```

    A structure value is an [`IndexMap`](https://docs.rs/indexmap) (members in order); add `indexmap` to your
    dependencies to build one.

=== "C#"

    ```csharp
    plc.Write("Counter", 0);
    plc.Write(("Tank.Setpoint", 75.5), ("Motor.Start", true));
    plc.Write("Recipe{5}", new[] { 10, 20, 30, 40, 50 });
    plc.Write("Tank", new Dictionary<string, object?> { ["Level"] = 0.0, ["Setpoint"] = 60.0 });
    plc.Write("Message", "Line 2 running");
    ```

=== "C++"

    ```cpp
    plc.write_tag("Counter", 0);
    plc.write({{"Tank.Setpoint", 75.5}, {"Motor.Start", true}});
    plc.write_tag("Recipe{5}", ciplink::Array{10, 20, 30, 40, 50});
    plc.write_tag("Tank", ciplink::Struct{{"Level", 0.0}, {"Setpoint", 60.0}});
    plc.write_tag("Message", "Line 2 running");
    ```

=== "C"

    ```c
    char *json = NULL;
    if (ciplink_write(plc,
            "[[\"Counter\", 0], [\"Tank.Setpoint\", 75.5], [\"Motor.Start\", true],"
            " [\"Recipe{5}\", [10, 20, 30, 40, 50]], [\"Tank\", {\"Level\": 0.0, \"Setpoint\": 60.0}],"
            " [\"Message\", \"Line 2 running\"]]",
            &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);   /* one result per pair */
        ciplink_string_free(json);
    }
    ```

If an array value is shorter than the element count, that tag isn't written and its result has an error; extra values
are ignored. A string longer than the tag's string type is an error too.

## Strings

`STRING` and any custom string type (a structure of a `LEN` DINT and a `DATA` SINT array) read and write as plain
strings, with no need to handle `LEN` and `DATA`.

## BOOL arrays and bit strings

BOOL arrays are stored in 32-bit words, which is why their size is a multiple of 32. `Flags[30]{5}` reads or writes
5 BOOLs starting at index 30. A write that covers part of a word uses a read-modify-write mask, so the other bits are
left as they are; a write spanning several words updates each word separately (not as one atomic operation).

A `BYTE`, `WORD`, `DWORD` or `LWORD` tag or member that isn't an array is a bit string: its value is a list of one
bool per bit, least significant first. Its bits are read and written as `Name.n`.

=== "Python"

    ```python
    plc.write("Flags[30]{5}", [True, False, True, True, False])
    print(plc.read("Status").value)      # [True, False, False, ...]: 16 bools for a WORD
    plc.write("Status.3", True)
    ```

=== "Rust"

    ```rust
    let bits = [true, false, true, true, false].into_iter().map(Value::Bool).collect();
    plc.write(&[("Flags[30]{5}", Value::Array(bits))])?;
    plc.write(&[("Status.3", Value::Bool(true))])?;
    ```

=== "C#"

    ```csharp
    plc.Write("Flags[30]{5}", new[] { true, false, true, true, false });
    plc.Write("Status.3", true);
    ```

=== "C++"

    ```cpp
    plc.write_tag("Flags[30]{5}", ciplink::Array{true, false, true, true, false});
    plc.write_tag("Status.3", true);
    ```

=== "C"

    ```c
    char *json = NULL;
    if (ciplink_write(plc, "[[\"Flags[30]{5}\", [true, false, true, true, false]], [\"Status.3\", true]]", &json)
            == CIPLINK_STATUS_OK)
        ciplink_string_free(json);
    ```

## Large arrays

One-dimensional arrays (other than BOOL arrays) of more than 65,535 elements are split into several requests and
returned as one result, for reads and writes alike. Such a transfer isn't a single snapshot or an atomic write.

## Polling

Keep one driver open around the polling loop and read all the tags in one call, so they share packets. With
`lazy_tags` only the tags you read are looked up. `examples/polling.py` in the repository is a complete example:

```sh
python -m examples.polling 192.0.2.10 Motor.Speed Motor.Running --interval 1 --lazy-tags
```
