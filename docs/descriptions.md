# Tag descriptions

The Description of a tag, member, array element or bit (`"Tank"`, `"Tank.Level"`, `"Recipe[3]"`, `"Status.3"`) is
read the way Studio 5000 reads it. Controllers only answer these metadata reads on a connection that has been
authenticated first, so call `authenticate_metadata` once per connection (again after a reconnect). It uses
credentials bundled with ciplink unless you pass your own (a signed certificate and its unencrypted DER RSA private
key). Authentication changes nothing in the controller.

Each description is a result like a read: the value is the text, and a tag without a Description has a
`not_found` error. `language` is the language code (0x7F, the default, is the project's language); `encoding` is
`utf-8` (default), `ascii`, `latin-1` or `cp1252`.

=== "Python"

    ```python
    from ciplink import LogixDriver

    with LogixDriver("192.0.2.10") as plc:
        auth = plc.authenticate_metadata()
        if not auth:
            raise SystemExit(f"metadata reads refused: {auth.error}")
        print(plc.get_tag_description("Tank.Level").value)
        for tag in plc.get_tag_descriptions("Counter", "Tank", "Recipe[3]"):
            print(tag.tag, tag.value if tag else tag.error)
    ```

=== "Rust"

    ```rust
    use ciplink::logix::driver::{LogixDriver, LogixOptions};
    use ciplink::logix::metadata::TextEncoding;

    let plc = LogixDriver::new("192.0.2.10", LogixOptions::default())?;
    plc.open()?;
    let auth = plc.authenticate_metadata(None);
    if !auth.is_ok() {
        return Err(format!("metadata reads refused: {:?}", auth.error).into());
    }
    for tag in plc.get_tag_descriptions(&["Counter", "Tank", "Recipe[3]"], 0x7F, TextEncoding::Utf8)? {
        println!("{} {:?} {:?}", tag.tag, tag.value, tag.error);
    }
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new LogixDriver("192.0.2.10");
    plc.Open();
    Tag auth = plc.AuthenticateMetadata();
    if (!auth.IsOk)
        throw new InvalidOperationException($"metadata reads refused: {auth.Error}");
    foreach (Tag tag in plc.GetTagDescriptions(new[] { "Counter", "Tank", "Recipe[3]" }))
        Console.WriteLine($"{tag.Name} {(tag.IsOk ? tag.Value : tag.Error)}");
    ```

=== "C++"

    ```cpp
    #include <iostream>
    #include "ciplink.hpp"

    ciplink::Logix plc("192.0.2.10");
    plc.open();
    if (!plc.authenticate_metadata())
        throw std::runtime_error("metadata reads refused");
    for (const ciplink::Tag& tag : plc.get_tag_descriptions({"Counter", "Tank", "Recipe[3]"}))
        std::cout << tag.tag << " " << (tag ? tag.value.as_string() : tag.error->message) << "\n";
    ```

=== "C"

    ```c
    char *json = NULL;
    if (ciplink_authenticate_metadata(plc, NULL, 0, NULL, 0, &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);     /* value true on success, else the result's error */
        ciplink_string_free(json);
    }
    const char *tags[] = {"Counter", "Tank", "Recipe[3]"};
    if (ciplink_get_tag_descriptions(plc, tags, 3, 0x7F, NULL, &json) == CIPLINK_STATUS_OK) {
        printf("%s\n", json);
        ciplink_string_free(json);
    }
    ```

Many descriptions share each request, so read them in one call rather than one by one.
