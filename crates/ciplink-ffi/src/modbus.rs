//! Modbus TCP, RTU and RTU over TCP: `ciplink_modbus_new` and the Modbus-only calls. A Modbus handle also takes
//! the generic calls (open, close, read, write, the async calls, subscriptions, connection events, socket
//! timeout); the CIP-only calls return [`CiplinkStatus::Unsupported`].

use super::*;
use ciplink_core::modbus::{DeviceInfo, ModbusOptions, TagMap, WordOrder, modbus_connector};

fn get_u16(o: &Map<String, Json>, key: &str, default: u16) -> FfiResult<u16> {
    match o.get(key) {
        None => Ok(default),
        Some(j) => j
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| FfiError::Invalid(format!("option {key} must be 0 to 65535"))),
    }
}

fn get_string<'a>(o: &'a Map<String, Json>, key: &str) -> FfiResult<Option<&'a str>> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s)),
        Some(_) => Err(FfiError::Invalid(format!("option {key} must be a string"))),
    }
}

fn modbus_options(o: &Map<String, Json>) -> FfiResult<ModbusOptions> {
    let d = ModbusOptions::default();
    let map = match (get_string(o, "map_file")?, get_string(o, "map_csv")?) {
        (Some(_), Some(_)) => {
            return Err(FfiError::Invalid(
                "pass map_file or map_csv, not both".into(),
            ));
        }
        (Some(path), None) => Some(TagMap::load(path)?),
        (None, Some(csv)) => Some(TagMap::from_csv(csv)?),
        (None, None) => None,
    };
    let socket_timeout = match o.get("socket_timeout") {
        None => d.socket_timeout,
        Some(j) => j
            .as_f64()
            .filter(|s| s.is_finite() && *s > 0.0)
            .map(Duration::from_secs_f64)
            .ok_or_else(|| {
                FfiError::Invalid("option socket_timeout must be positive seconds".into())
            })?,
    };
    let word_order = match get_string(o, "word_order")? {
        None => d.word_order,
        Some(s) => WordOrder::parse(s).ok_or_else(|| {
            FfiError::Invalid(format!(
                "option word_order {s:?} is not ABCD, CDAB, BADC or DCBA"
            ))
        })?,
    };
    Ok(ModbusOptions {
        map,
        socket_timeout,
        max_registers: get_u16(o, "max_registers", d.max_registers)?,
        max_bits: get_u16(o, "max_bits", d.max_bits)?,
        max_gap: get_u16(o, "max_gap", d.max_gap)?,
        word_order,
        write_multiple: get_bool(o, "write_multiple", d.write_multiple)?,
        keep_alive_address: get_string(o, "keep_alive_address")?.map(str::to_owned),
    })
}

fn modbus<'a>(h: &'a CiplinkDriver, what: &'static str) -> FfiResult<&'a ModbusDriver> {
    match &h.driver {
        Driver::Modbus(d) => Ok(d),
        _ => Err(FfiError::Unsupported(what)),
    }
}

/// A unit argument: negative for the path's unit.
fn unit_arg(unit: i32) -> FfiResult<Option<u8>> {
    if unit < 0 {
        return Ok(None);
    }
    u8::try_from(unit)
        .map(Some)
        .map_err(|_| FfiError::Invalid(format!("unit {unit} is not 0 to 255")))
}

fn device_info_json(info: &DeviceInfo) -> String {
    serde_json::json!({
        "vendor_name": info.vendor_name,
        "product_code": info.product_code,
        "revision": info.revision,
        "vendor_url": info.vendor_url,
        "product_name": info.product_name,
        "model_name": info.model_name,
        "user_application_name": info.user_application_name,
    })
    .to_string()
}

fn tags_json(map: &TagMap) -> String {
    let rows: Vec<Json> = map
        .tags()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "area": t.area.as_str(),
                "address": t.address,
                "bit": t.bit,
                "type": t.data_type.as_str(),
                "cip_type": t.type_name(),
                "count": t.count,
                "order": t.order.map(WordOrder::as_str),
                "unit": t.unit,
                "scale": t.scale,
                "offset": t.offset,
                "units": t.units,
                "description": t.description,
                "writable": t.writable,
            })
        })
        .collect();
    Json::Array(rows).to_string()
}

/// Creates a Modbus driver for `path`: `tcp://host[:port][?unit=N]` (Modbus TCP, port 502, unit 1 by default),
/// `rtu://PORT[?baud=..&parity=..&data=..&stop=..&unit=N]` (RTU on a serial port) or
/// `rtu+tcp://host[:port][?unit=N]` (RTU frames over TCP, for serial gateways). Not connected until
/// [`ciplink_open`]. Tag names come from the map file; anything else is a plain address such as `hr100:float32`
/// (0-based protocol addresses: holding register 40001 is `hr0`).
///
/// `options_json` may be NULL or `{}`; keys (all optional): `map_file` (path of the map CSV), `map_csv` (the CSV
/// text itself; not with `map_file`), `socket_timeout` (seconds, default 1), `max_registers` (most registers per
/// read, 1 to 125, default 125), `max_bits` (most coils or discrete inputs per read, 1 to 2000, default 2000),
/// `max_gap` (most unrequested registers or bits between two tags merged into one read, default 8), `word_order`
/// (of tags without one: `"ABCD"` (default), `"CDAB"`, `"BADC"`, `"DCBA"`), `write_multiple` (always FC15/16,
/// default false), `keep_alive_address` (a plain address the keep-alive reads instead of sending FC08, default
/// null), `reconnect` (true), `reconnect_min` (0.1), `reconnect_max` (10), `keep_alive` (seconds, or null for
/// never; absent: 30 over TCP, never for `rtu://`).
///
/// # Safety
/// As [`ciplink_logix_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_modbus_new(
    path: *const c_char,
    options_json: *const c_char,
    out: *mut *mut CiplinkDriver,
) -> CiplinkStatus {
    create(path, options_json, out, |path, o| {
        let session = session::session_options_with(o, ModbusDriver::default_session(path)?)?;
        Ok(Driver::Modbus(Box::new(ModbusDriver::with_session(
            path,
            modbus_options(o)?,
            session,
            modbus_connector(),
        )?)))
    })
}

/// Reads the device identification (FC43 / MEI 14) of `unit` (negative for the path's unit) as a JSON object:
/// `{"vendor_name": str, "product_code": str, "revision": str, "vendor_url": str|null, "product_name":
/// str|null, "model_name": str|null, "user_application_name": str|null}`. A device without it answers with an
/// exception: [`CiplinkStatus::Response`].
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_modbus_device_info(
    handle: *const CiplinkDriver,
    unit: i32,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let info = modbus(h, "device_info")?.device_info(unit_arg(unit)?)?;
        put_string(out_json, device_info_json(&info))
    })
}

/// The map file's tags as a JSON array of rows in file order (empty without a map): `{"name", "area"
/// ("coil", "discrete", "holding", "input"), "address" (0-based), "bit" (int|null), "type" (the map type, e.g.
/// "float32"), "cip_type" (the type name reads report, e.g. "REAL", "LREAL" when scaled), "count", "order"
/// (str|null), "unit" (int|null), "scale" (number|null), "offset" (number|null), "units", "description",
/// "writable"}`. No I/O.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_modbus_tags(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        put_string(out_json, tags_json(modbus(h, "modbus_tags")?.map()))
    })
}

/// Sends one raw PDU (function code and data) to `unit` (negative for the path's unit) and returns the reply PDU
/// in `*out` / `*out_len`; free it with [`ciplink_bytes_free`]. An exception reply is
/// [`CiplinkStatus::Response`]. For functions the driver does not wrap (FC23, file records, ...).
///
/// # Safety
/// `handle` is NULL or a live handle; `pdu` points to `len` readable bytes; `out` and `out_len` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_modbus_send_pdu(
    handle: *const CiplinkDriver,
    unit: i32,
    pdu: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out)?;
        let pdu = opt_bytes(pdu, len, "pdu")?
            .filter(|p| !p.is_empty())
            .ok_or_else(|| FfiError::Invalid("pdu is empty".into()))?;
        let reply = modbus(h, "send_pdu")?.send_pdu(unit_arg(unit)?, pdu)?;
        put_bytes(out, out_len, reply)
    })
}

#[cfg(test)]
#[path = "modbus_tests.rs"]
mod tests;
