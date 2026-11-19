//! The S7comm-plus driver (Siemens S7-1500 / S7-1200 over TLS): its constructor, its two extra calls, and the
//! JSON of its tags, types, symbols and CPU information for the generic calls ([`ciplink_tags`],
//! [`ciplink_data_types`], [`ciplink_tag_list`], [`ciplink_tag_info`], [`ciplink_info`],
//! [`ciplink_get_plc_name`], [`ciplink_get_plc_info`]).

use super::*;
use ciplink_core::s7plus::{CpuInfo, S7Kind, S7PlusDriver, S7PlusOptions, S7Symbol, S7Tag, S7Type};
use serde_json::json;

fn options(o: &Map<String, Json>) -> FfiResult<S7PlusOptions> {
    let d = S7PlusOptions::default();
    let socket_timeout = match o.get("socket_timeout") {
        None => d.socket_timeout,
        Some(Json::Null) => None,
        Some(j) => Some(Duration::from_secs_f64(
            j.as_f64()
                .filter(|s| s.is_finite() && *s >= 0.0)
                .ok_or_else(|| {
                    FfiError::Invalid("option socket_timeout must be seconds or null".into())
                })?,
        )),
    };
    let tls_fingerprint = match o.get("tls_fingerprint") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => Some(s.clone()),
        Some(_) => {
            return Err(FfiError::Invalid(
                "option tls_fingerprint must be a string".into(),
            ));
        }
    };
    Ok(S7PlusOptions {
        socket_timeout,
        init_tags: get_bool(o, "init_tags", d.init_tags)?,
        tls_fingerprint,
    })
}

/// Creates an S7comm-plus driver for a Siemens S7-1500 / S7-1200 CPU with secure PG/HMI communication (TLS,
/// firmware 2.9 and later) at `path` (`host` or `host:port`, default port 102). Not connected until
/// [`ciplink_open`]; a refused COTP connection is a [`CiplinkStatus::Comm`] error there.
///
/// `options_json` may be NULL or `{}`; keys (all optional): `socket_timeout` (seconds, null to block forever,
/// default 10), `init_tags` (browse on open, true), `tls_fingerprint` (SHA-256 of the PLC certificate to require,
/// hex with or without `:`; null accepts any, the default), and `reconnect`, `reconnect_min`, `reconnect_max`,
/// `keep_alive` as [`ciplink_logix_new`] (`keep_alive` default 15). A malformed fingerprint is a
/// [`CiplinkStatus::Request`] error.
///
/// Tag names are TIA style (`Line1.Conveyor.Speed`, `Line1.Items[3]`, PLC tags by their bare name). Besides
/// the session calls (read, write, async, subscribe, connection events, socket timeout) the generic calls
/// [`ciplink_tags`] (top-level tags), [`ciplink_data_types`], [`ciplink_tag_list`] (the flat symbol list; its
/// program, cache and filter arguments are ignored), [`ciplink_tag_info`], [`ciplink_get_plc_name`],
/// [`ciplink_get_plc_info`] (CPU information) and [`ciplink_info`] (CPU information plus `fingerprint`) work on
/// it; the CIP-only calls return [`CiplinkStatus::Unsupported`].
///
/// # Safety
/// As [`ciplink_logix_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_s7plus_new(
    path: *const c_char,
    options_json: *const c_char,
    out: *mut *mut CiplinkDriver,
) -> CiplinkStatus {
    create(path, options_json, out, |path, o| {
        let mut session = session::session_options(o)?;
        if !o.contains_key("keep_alive") {
            session.keep_alive = S7PlusOptions::default_session().keep_alive;
        }
        Ok(Driver::S7Plus(Box::new(S7PlusDriver::with_session(
            path,
            options(o)?,
            session,
        )?)))
    })
}

fn s7plus<'a>(h: &'a CiplinkDriver, what: &'static str) -> FfiResult<&'a S7PlusDriver> {
    match &h.driver {
        Driver::S7Plus(d) => Ok(d),
        _ => Err(FfiError::Unsupported(what)),
    }
}

/// The SHA-256 fingerprint (`"AB:CD:..."`) of the certificate the PLC presented at the latest TLS handshake, as a
/// JSON string, or JSON `null` before one. A handshake refused by the `tls_fingerprint` pin still sets it.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_json` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_s7plus_fingerprint(
    handle: *const CiplinkDriver,
    out_json: *mut *mut c_char,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        check_out(out_json)?;
        let fp = s7plus(h, "s7plus_fingerprint")?.certificate_fingerprint();
        put_string(out_json, json!(fp).to_string())
    })
}

/// Browses the PLC's symbol table again; `*out_changed` is true if the tags or types changed.
///
/// # Safety
/// `handle` is NULL or a live handle; `out_changed` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciplink_s7plus_refresh_tags(
    handle: *const CiplinkDriver,
    out_changed: *mut bool,
) -> CiplinkStatus {
    with_handle(handle, |h| {
        if out_changed.is_null() {
            return Err(FfiError::Invalid("output pointer is NULL".into()));
        }
        let changed = s7plus(h, "s7plus_refresh_tags")?.refresh_tags()?;
        // SAFETY: not NULL and the caller passes a writable bool.
        unsafe { *out_changed = changed };
        Ok(())
    })
}

// ------------------------------------------------------------------------------------------------ JSON

fn kind_name(kind: S7Kind) -> &'static str {
    match kind {
        S7Kind::Elementary => "elementary",
        S7Kind::String => "string",
        S7Kind::Struct => "struct",
        S7Kind::DataBlock => "data_block",
        S7Kind::Area => "area",
    }
}

fn tag_json(t: &S7Tag) -> Json {
    json!({
        "name": t.name,
        "type": t.type_name,
        "kind": kind_name(t.kind),
        "softdatatype": t.softdatatype,
        "dims": t.dims,
        "lower_bounds": t.lower_bounds,
        "string_length": t.string_length,
        "lid": t.lid,
        "member_crc": t.member_crc,
        "hmi_visible": t.hmi_visible,
        "hmi_accessible": t.hmi_accessible,
        "hmi_read_only": t.hmi_read_only,
    })
}

fn type_json(t: &S7Type) -> Json {
    let members: Map<String, Json> = t
        .members
        .iter()
        .map(|(k, m)| (k.clone(), tag_json(m)))
        .collect();
    json!({
        "name": t.name,
        "rid": t.rid,
        "interface_timestamp": t.interface_timestamp,
        "members": members,
    })
}

fn symbol_json(s: &S7Symbol) -> Json {
    json!({
        "name": s.name,
        "type": s.type_name,
        "dims": s.dims,
        "access": s.access,
        "crc": s.crc,
        "hmi_visible": s.hmi_visible,
        "hmi_accessible": s.hmi_accessible,
        "hmi_read_only": s.hmi_read_only,
    })
}

fn cpu_info_json(i: &CpuInfo) -> Map<String, Json> {
    let j = json!({
        "name": i.name,
        "order_number": i.order_number,
        "serial_number": i.serial_number,
        "hardware_version": i.hardware_version,
        "firmware": i.firmware,
        "engineering_version": i.engineering_version,
        "project": i.project,
        "protection_level": i.protection_level,
        "max_read": i.max_read,
        "max_write": i.max_write,
    });
    match j {
        Json::Object(m) => m,
        _ => Map::new(),
    }
}

/// Top-level tags by name.
pub(crate) fn tags(d: &S7PlusDriver) -> String {
    let m: Map<String, Json> = d
        .tags()
        .iter()
        .map(|(k, t)| (k.clone(), tag_json(t)))
        .collect();
    Json::Object(m).to_string()
}

/// Structure types by name.
pub(crate) fn data_types(d: &S7PlusDriver) -> String {
    let m: Map<String, Json> = d
        .data_types()
        .iter()
        .map(|(k, t)| (k.clone(), type_json(t)))
        .collect();
    Json::Object(m).to_string()
}

/// The flat symbol list.
pub(crate) fn tag_list(d: &S7PlusDriver) -> FfiResult<String> {
    let list: Vec<Json> = d.tag_list()?.iter().map(symbol_json).collect();
    Ok(Json::Array(list).to_string())
}

/// One symbol.
pub(crate) fn tag_info(d: &S7PlusDriver, name: &str) -> FfiResult<String> {
    Ok(symbol_json(&d.get_tag_info(name)?).to_string())
}

/// The PLC name: the one read at open, else read now; JSON null if the PLC has none.
pub(crate) fn plc_name(d: &S7PlusDriver) -> FfiResult<String> {
    let name = match d.name() {
        Some(n) => Some(n),
        None => d.get_plc_info()?.name,
    };
    Ok(json!(name).to_string())
}

/// The CPU information, with `fingerprint` added when `fingerprint` is true.
pub(crate) fn plc_info(d: &S7PlusDriver, fingerprint: bool) -> FfiResult<String> {
    let mut m = cpu_info_json(&d.get_plc_info()?);
    if fingerprint {
        m.insert("fingerprint".into(), json!(d.certificate_fingerprint()));
    }
    Ok(Json::Object(m).to_string())
}

#[cfg(test)]
#[path = "s7plus_tests.rs"]
mod tests;
