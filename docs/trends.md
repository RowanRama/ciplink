# Trends

For data faster than polling can give, a trend has the controller itself sample tags at a fixed period (down to
1 ms) into its trend buffer, the trend object Studio 5000 uses. The driver uploads the samples in batches on a
connection of its own, each with the controller's timestamp, so no sample depends on network timing.

- A pen is any atomic tag, member or array element of up to 32 bits (BOOL, SINT, INT, DINT, USINT, UINT, UDINT,
  REAL) or a bit (`Tag.3`). 64-bit types (LINT, LREAL) can't be trended.
- `period_ms` is the sample period, 1 ms or more, in whole microseconds (default 10 ms).
- `capacity` (default 4096) bounds the samples waiting to be read. When it's full the oldest are dropped and
  counted as dropped.
- `duration` (seconds) stops the trend by itself; without it the trend runs until closed.
- The controller deletes the trend when it's closed or when its connection drops.

Each sample has the controller time (`timestamp_us`, microseconds since 1970 UTC), the time since the trend started
(`elapsed_us`) and one value per pen.

=== "Python"

    ```python
    import time
    from ciplink import LogixDriver

    with LogixDriver("192.0.2.10") as plc:
        with plc.trend("Motor.Speed", "Tank.Level", "Motor.Running", period_ms=1, duration=5) as trend:
            while trend.running:
                time.sleep(0.1)
                for sample in trend.read():          # TrendSample(timestamp_us, elapsed_us, values)
                    print(sample.timestamp, sample.values)
    ```

    `trend.pens`, `received_samples`, `dropped_samples` and `error` describe the trend; leaving the `with` block
    (or `trend.close()`) stops it.

=== "Rust"

    ```rust
    use ciplink::logix::driver::{LogixDriver, LogixOptions};
    use ciplink::logix::trend::TrendOptions;
    use std::time::Duration;

    let plc = LogixDriver::new("192.0.2.10", LogixOptions::default())?;
    plc.open()?;
    let trend = plc.trend(
        &["Motor.Speed", "Tank.Level", "Motor.Running"],
        TrendOptions { period: Duration::from_millis(1), duration: Some(Duration::from_secs(5)), ..TrendOptions::default() },
    )?;
    while trend.running() {
        std::thread::sleep(Duration::from_millis(100));
        for sample in trend.read()? {
            println!("{} {:?}", sample.timestamp_us, sample.values);
        }
    }
    trend.close()?;
    ```

=== "C#"

    ```csharp
    using Ciplink;

    using var plc = new LogixDriver("192.0.2.10");
    plc.Open();
    using Trend trend = plc.Trend(new[] { "Motor.Speed", "Tank.Level", "Motor.Running" },
        new TrendOptions { PeriodMs = 1, Duration = TimeSpan.FromSeconds(5) });
    while (trend.Running)
    {
        Thread.Sleep(100);
        foreach (TrendSample sample in trend.Read())
            Console.WriteLine($"{sample.Timestamp:O} {string.Join(", ", sample.Values)}");
    }
    trend.Close();
    ```

=== "C++"

    ```cpp
    #include <chrono>
    #include <iostream>
    #include <thread>
    #include "ciplink.hpp"

    ciplink::Logix plc("192.0.2.10");
    plc.open();
    ciplink::Trend trend = plc.trend({"Motor.Speed", "Tank.Level", "Motor.Running"}, /*period_ms*/ 1,
                                     /*capacity*/ 4096, /*duration*/ 5.0);
    while (trend.running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        for (const ciplink::TrendSample& s : trend.read())
            std::cout << s.timestamp_us << " " << ciplink::to_json(ciplink::Value(s.values)) << "\n";
    }
    trend.close();
    ```

=== "C"

    ```c
    #include <stdio.h>
    #include <string.h>
    #include <windows.h>     /* Sleep; on Linux and macOS use <unistd.h> and usleep */
    #include "ciplink.h"

    /* plc: an open Logix driver */
    const char *pens[] = {"Motor.Speed", "Tank.Level", "Motor.Running"};
    CiplinkTrend *trend = NULL;
    if (ciplink_trend_start(plc, pens, 3, "{\"period_ms\": 1, \"duration\": 5}", &trend) == CIPLINK_STATUS_OK) {
        for (;;) {
            char *json = NULL;
            if (ciplink_trend_read(trend, &json) != CIPLINK_STATUS_OK)
                break;               /* the trend failed and every sample was read */
            printf("%s\n", json);    /* [{"timestamp_us": ..., "elapsed_us": ..., "values": [...]}, ...] */
            ciplink_string_free(json);
            char *info = NULL;
            ciplink_trend_info(trend, &info);
            bool running = strstr(info, "\"running\":true") != NULL;
            ciplink_string_free(info);
            if (!running)
                break;
            Sleep(100);              /* usleep(100000) on Linux and macOS */
        }
        ciplink_trend_close(trend);
        ciplink_trend_free(trend);
    }
    ```

A trend needs a Logix controller that supports the trend object (ControlLogix and CompactLogix). The
[simulator](simulator.md) simulates it too.
