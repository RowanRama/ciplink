//! The tag definitions as the reference driver's Python objects: `tags`, `data_types`, `tags_json`, the dicts of
//! `get_tag_info` and `get_tag_list`, built here from the core's [`Definitions`] with the C API.
//!
//! As in the reference driver, one data type dict exists per data type object: a tag's `data_type` is the very
//! dict in `data_types` (and in its parents' `internal_tags`), and it carries the type's `type_class`, built
//! once per data type.  The built objects are kept until the core's definitions version changes (an upload, a
//! reload after an online edit, a lazy load, shared tags); data type dicts are kept across rebuilds as long as
//! the core keeps the data type object, so only what changed is built again.  Array type classes are shared by
//! (length, element type): they hold nothing else.

use std::collections::HashMap;
use std::sync::Arc;

use ciplink::logix::driver::{AoiProbe, Definitions};
use ciplink::logix::types::{DataType, MemberInfo, TagDef, TemplateMakeup, TypeRef, strip_array};
use ciplink::types::Elementary;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyList, PySet, PyString, PyTuple, PyWeakrefReference};

static STRUCT_TAG: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static FIXED_SIZE_STRING: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static ARRAY: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static DATA_TYPES_GET: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static TAG_DICT: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static GC_ISENABLED: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static GC_DISABLE: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static GC_ENABLE: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

fn attr<'py>(
    py: Python<'py>,
    cell: &'static PyOnceLock<Py<PyAny>>,
    module: &str,
    path: &[&str],
) -> PyResult<Bound<'py, PyAny>> {
    cell.get_or_try_init(py, || {
        let mut obj = py.import(module)?.into_any();
        for name in path {
            obj = obj.getattr(*name)?;
        }
        Ok::<_, PyErr>(obj.unbind())
    })
    .map(|obj| obj.bind(py).clone())
}

/// Runs `f` with Python's cyclic garbage collector paused: building thousands of dicts would otherwise run
/// collections that walk every live object, for nothing (what is built here has no garbage cycles).
pub(crate) fn without_gc<T>(py: Python<'_>, f: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    let enabled = attr(py, &GC_ISENABLED, "gc", &["isenabled"])?
        .call0()?
        .is_truthy()?;
    if enabled {
        attr(py, &GC_DISABLE, "gc", &["disable"])?.call0()?;
    }
    let result = f();
    if enabled {
        attr(py, &GC_ENABLE, "gc", &["enable"])?.call0()?;
    }
    result
}

/// A data type dict kept for the data type object it was built from.
struct TypeEntry {
    /// Keeps the data type object, so its address (the key) is not reused while the entry exists.
    _data_type: Arc<DataType>,
    dict: Py<PyDict>,
    probe: Option<AoiProbe>,
}

/// What the Python driver built from one definitions version, and the pieces reused by the next build.
#[derive(Default)]
pub(crate) struct DefsCache {
    version: Option<u64>,
    /// The core's tags generation and how many of its tags `tags` holds: lazy loads only add tags, which are
    /// then added to `tags` (the same dict, as in the reference driver).
    tags_generation: u64,
    tags_count: usize,
    tags: Option<Py<PyDict>>,
    data_types: Option<Py<PyDict>>,
    /// Lowercase tag name to the first tag of that name, for case-insensitive lookups (built on first use).
    lower: Option<HashMap<String, String>>,
    types: HashMap<usize, TypeEntry>,
    /// `Array(length, element)` by (length, element address), the element kept alive with it.
    arrays: HashMap<(usize, usize), ArrayEntry>,
    /// `DataTypes.get(name)` by atomic type name.
    atomics: HashMap<Option<&'static str>, Py<PyAny>>,
}

/// An element type and its array type class (the element is kept so its address, the key, is not reused).
type ArrayEntry = (Py<PyAny>, Py<PyAny>);

fn key(data_type: &Arc<DataType>) -> usize {
    Arc::as_ptr(data_type) as usize
}

impl DefsCache {
    /// True while the built objects are those of `version`.
    pub(crate) fn is_current(&self, version: u64) -> bool {
        self.version == Some(version) && self.tags.is_some()
    }

    /// The (tags generation, tag count) to ask the core's definitions since.
    pub(crate) fn since(&self) -> (u64, usize) {
        match self.tags {
            Some(_) => (self.tags_generation, self.tags_count),
            None => (u64::MAX, 0),
        }
    }

    pub(crate) fn tags<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyDict>> {
        self.tags.as_ref().map(|t| t.bind(py).clone())
    }

    pub(crate) fn data_types<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyDict>> {
        self.data_types.as_ref().map(|t| t.bind(py).clone())
    }

    /// Builds `tags` and `data_types` from `defs`, or adds its tags to `tags` when `defs` holds only those
    /// added since (`tags_from`); a weak reference to `owner` (the core driver) goes on a new tags dict, for
    /// `plc2._tags = plc1.tags`.
    pub(crate) fn rebuild(
        &mut self,
        py: Python<'_>,
        defs: &Definitions,
        owner: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let probes: HashMap<usize, &AoiProbe> =
            defs.probes.iter().map(|(dt, p)| (key(dt), p)).collect();
        let kept = match &self.tags {
            Some(tags) if defs.tags_from > 0 && defs.tags_from == self.tags_count => {
                Some(tags.bind(py).clone())
            }
            _ => None,
        };
        // a whole build drops what it does not use again: data types and array classes of older definitions
        let mut builder = Builder {
            py,
            old: std::mem::take(&mut self.types),
            new: HashMap::with_capacity(defs.data_types.len()),
            old_arrays: std::mem::take(&mut self.arrays),
            new_arrays: HashMap::new(),
            probes,
            atomics: &mut self.atomics,
        };
        let (tags, data_types) = without_gc(py, || {
            let data_types = PyDict::new(py);
            for (name, dt) in &defs.data_types {
                data_types.set_item(name.as_deref(), builder.data_type(dt)?)?;
            }
            let tags = match &kept {
                Some(tags) => tags.clone(),
                None => {
                    let tags = attr(py, &TAG_DICT, "ciplink.logix_driver", &["_TagDict"])?
                        .call0()?
                        .cast_into::<PyDict>()?;
                    tags.setattr(intern!(py, "_owner"), PyWeakrefReference::new(owner)?)?;
                    tags
                }
            };
            for (name, tag) in &defs.tags {
                tags.set_item(name, builder.tag(tag)?)?;
            }
            Ok((tags, data_types))
        })?;
        self.types = builder.new;
        self.arrays = builder.new_arrays;
        if kept.is_some() {
            // the tags built before still use them
            self.types.extend(builder.old);
            self.arrays.extend(builder.old_arrays);
        }
        self.tags_generation = defs.tags_generation;
        self.tags_count = defs.tags_from + defs.tags.len();
        self.tags = Some(tags.unbind());
        self.data_types = Some(data_types.unbind());
        self.lower = None;
        self.version = Some(defs.version);
        Ok(())
    }

    /// Dicts of tags not (or not yet) in `tags`, e.g. a `get_tag_list` without cache, sharing the data type
    /// dicts of `data_types`.
    pub(crate) fn tag_dicts<'py>(
        &mut self,
        py: Python<'py>,
        tags: &[TagDef],
        probes: &[(Arc<DataType>, AoiProbe)],
    ) -> PyResult<Bound<'py, PyList>> {
        let probes = probes.iter().map(|(dt, p)| (key(dt), p)).collect();
        let mut builder = Builder {
            py,
            old: std::mem::take(&mut self.types),
            new: HashMap::new(),
            old_arrays: std::mem::take(&mut self.arrays),
            new_arrays: HashMap::new(),
            probes,
            atomics: &mut self.atomics,
        };
        let items = without_gc(py, || {
            tags.iter()
                .map(|t| builder.tag(t))
                .collect::<PyResult<Vec<_>>>()
        });
        // everything is kept: the entries used were moved to new
        let mut types = builder.new;
        types.extend(builder.old);
        self.types = types;
        let mut arrays = builder.new_arrays;
        arrays.extend(builder.old_arrays);
        self.arrays = arrays;
        PyList::new(py, items?)
    }

    /// The dict `get_tag_info(name)` returns, from the built tags; None if a name is not found there (the
    /// caller then asks the core, which loads a lazy tag or raises the reference driver's error).
    pub(crate) fn tag_info<'py>(
        &mut self,
        py: Python<'py>,
        base: &str,
        attrs: &[String],
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let Some(tags) = self.tags(py) else {
            return Ok(None);
        };
        let base = strip_array(base);
        let mut data = match tags.get_item(base)? {
            Some(d) => d,
            None => {
                let lower = match &mut self.lower {
                    Some(lower) => lower,
                    empty => {
                        let mut index = HashMap::with_capacity(tags.len());
                        for k in tags.keys() {
                            let k = k.cast_into::<PyString>()?.to_cow()?.into_owned();
                            index.entry(k.to_lowercase()).or_insert(k);
                        }
                        empty.insert(index)
                    }
                };
                match lower.get(&base.to_lowercase()) {
                    Some(name) => match tags.get_item(name)? {
                        Some(d) => d,
                        None => return Ok(None),
                    },
                    None => return Ok(None),
                }
            }
        };
        for attr in attrs {
            let Ok(dict) = data.cast::<PyDict>() else {
                return Ok(None);
            };
            let Some(data_type) = dict.get_item(intern!(py, "data_type"))? else {
                return Ok(None);
            };
            let Ok(data_type) = data_type.cast_into::<PyDict>() else {
                return Ok(None);
            };
            let Some(members) = data_type.get_item(intern!(py, "internal_tags"))? else {
                return Ok(None);
            };
            let Ok(members) = members.cast_into::<PyDict>() else {
                return Ok(None);
            };
            let attr = strip_array(attr);
            data = match members.get_item(attr)? {
                Some(d) => d,
                None => {
                    let lower = attr.to_lowercase();
                    let mut found = None;
                    for (k, v) in members.iter() {
                        if k.cast::<PyString>()?.to_cow()?.to_lowercase() == lower {
                            found = Some(v);
                            break;
                        }
                    }
                    match found {
                        Some(v) => v,
                        None => return Ok(None),
                    }
                }
            };
        }
        Ok(data.cast_into::<PyDict>().ok())
    }
}

struct Builder<'a, 'py> {
    py: Python<'py>,
    old: HashMap<usize, TypeEntry>,
    new: HashMap<usize, TypeEntry>,
    old_arrays: HashMap<(usize, usize), ArrayEntry>,
    new_arrays: HashMap<(usize, usize), ArrayEntry>,
    probes: HashMap<usize, &'a AoiProbe>,
    atomics: &'a mut HashMap<Option<&'static str>, Py<PyAny>>,
}

fn makeup_dict<'py>(py: Python<'py>, m: &TemplateMakeup) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item(
        intern!(py, "object_definition_size"),
        m.object_definition_size,
    )?;
    d.set_item(intern!(py, "structure_size"), m.structure_size)?;
    d.set_item(intern!(py, "member_count"), m.member_count)?;
    d.set_item(intern!(py, "structure_handle"), m.structure_handle)?;
    Ok(d)
}

fn probe_dict<'py>(py: Python<'py>, p: &AoiProbe) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item(intern!(py, "whole_read"), p.whole_read)?;
    d.set_item(intern!(py, "readable"), PyList::new(py, &p.readable)?)?;
    d.set_item(intern!(py, "refused"), PyList::new(py, &p.refused)?)?;
    Ok(d)
}

impl<'py> Builder<'_, 'py> {
    /// `DataTypes.get(name)`: the class of an atomic type (None for an unknown one).
    fn atomic(&mut self, e: Option<Elementary>) -> PyResult<Bound<'py, PyAny>> {
        let name = e.map(Elementary::name);
        if let Some(tc) = self.atomics.get(&name) {
            return Ok(tc.bind(self.py).clone());
        }
        let tc = attr(
            self.py,
            &DATA_TYPES_GET,
            "ciplink.cip",
            &["DataTypes", "get"],
        )?
        .call1((name,))?;
        self.atomics.insert(name, tc.clone().unbind());
        Ok(tc)
    }

    /// `Array(length_=length, element_type_=element)`, shared by (length, element).
    fn array(&mut self, length: usize, element: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let k = (length, element.as_ptr() as usize);
        if let Some((_, tc)) = self.new_arrays.get(&k) {
            return Ok(tc.bind(self.py).clone());
        }
        if let Some(entry) = self.old_arrays.remove(&k) {
            let tc = entry.1.bind(self.py).clone();
            self.new_arrays.insert(k, entry);
            return Ok(tc);
        }
        let py = self.py;
        let kwargs = PyDict::new(py);
        kwargs.set_item(intern!(py, "length_"), length)?;
        kwargs.set_item(intern!(py, "element_type_"), element)?;
        let tc = attr(py, &ARRAY, "ciplink.cip", &["Array"])?.call((), Some(&kwargs))?;
        self.new_arrays
            .insert(k, (element.clone().unbind(), tc.clone().unbind()));
        Ok(tc)
    }

    /// The dict of a data type object, built once (with its type class) and shared.
    fn data_type(&mut self, dt: &Arc<DataType>) -> PyResult<Bound<'py, PyDict>> {
        let py = self.py;
        let k = key(dt);
        if let Some(entry) = self.new.get(&k) {
            return Ok(entry.dict.bind(py).clone());
        }
        let probe = self.probes.get(&k).map(|p| (*p).clone());
        if let Some(mut entry) = self.old.remove(&k) {
            let dict = entry.dict.bind(py).clone();
            if entry.probe != probe {
                if let Some(p) = &probe {
                    dict.set_item(intern!(py, "aoi"), probe_dict(py, p)?)?;
                }
                entry.probe = probe;
            }
            self.new.insert(k, entry);
            // the nested types are reused too
            for member in dt.internal_tags.values() {
                if let TypeRef::Struct(nested) = &member.data_type {
                    self.data_type(nested)?;
                }
            }
            return Ok(dict);
        }

        let dict = PyDict::new(py);
        dict.set_item(intern!(py, "name"), dt.name.as_deref())?;
        let internal = PyDict::new(py);
        dict.set_item(intern!(py, "internal_tags"), &internal)?;
        let struct_members = PyList::empty(py);
        let bit_members = PyDict::new(py);
        for (name, member) in &dt.internal_tags {
            let m = self.member(member)?;
            internal.set_item(name, &m)?;
            match member.bit {
                Some(bit) if member.data_type == TypeRef::Atomic(Some(Elementary::Bool)) => {
                    bit_members.set_item(name, (member.offset, bit))?;
                }
                _ => {
                    let tc = m
                        .get_item(intern!(py, "type_class"))?
                        .unwrap_or_else(|| py.None().into_bound(py));
                    struct_members.append((tc.call1((name,))?, member.offset))?;
                }
            }
        }
        dict.set_item(intern!(py, "attributes"), PyList::new(py, &dt.attributes)?)?;
        dict.set_item(intern!(py, "template"), makeup_dict(py, &dt.template)?)?;
        let size = i64::from(dt.template.structure_size);
        if let Some(n) = dt.string {
            dict.set_item(intern!(py, "string"), n)?;
            let kwargs = PyDict::new(py);
            kwargs.set_item(intern!(py, "max_len_"), n)?;
            let tc = attr(
                py,
                &FIXED_SIZE_STRING,
                "ciplink.custom_types",
                &["FixedSizeString"],
            )?
            .call((size - 4,), Some(&kwargs))?;
            dict.set_item(intern!(py, "type_class"), tc)?;
        } else {
            dict.set_item(
                intern!(py, "_struct_members"),
                (&struct_members, &bit_members),
            )?;
            let kwargs = PyDict::new(py);
            kwargs.set_item(intern!(py, "bit_members"), &bit_members)?;
            kwargs.set_item(intern!(py, "struct_size"), size)?;
            kwargs.set_item(
                intern!(py, "private_members"),
                PySet::new(py, &dt.private_members)?,
            )?;
            let args = PyTuple::new(py, struct_members.iter())?;
            let tc = attr(py, &STRUCT_TAG, "ciplink.custom_types", &["StructTag"])?
                .call(args, Some(&kwargs))?;
            dict.set_item(intern!(py, "type_class"), tc)?;
        }
        if let Some(p) = &probe {
            dict.set_item(intern!(py, "aoi"), probe_dict(py, p)?)?;
        }
        self.new.insert(
            k,
            TypeEntry {
                _data_type: Arc::clone(dt),
                dict: dict.clone().unbind(),
                probe,
            },
        );
        Ok(dict)
    }

    /// A member's dict (an entry of `internal_tags`).
    fn member(&mut self, m: &MemberInfo) -> PyResult<Bound<'py, PyDict>> {
        let py = self.py;
        let d = PyDict::new(py);
        d.set_item(intern!(py, "offset"), m.offset)?;
        d.set_item(intern!(py, "tag_type"), m.data_type.tag_type())?;
        let (data_type, mut tc) = self.type_ref(&m.data_type)?;
        d.set_item(intern!(py, "data_type"), data_type)?;
        d.set_item(intern!(py, "data_type_name"), m.data_type.name())?;
        if let Some(bit) = m.bit {
            d.set_item(intern!(py, "bit"), bit)?;
        }
        if let Some(array) = m.array {
            d.set_item(intern!(py, "array"), array)?;
            let is_bool = m.data_type == TypeRef::Atomic(Some(Elementary::Bool));
            if array > 0 && !is_bool {
                tc = self.array(usize::from(array), &tc)?;
            }
        }
        d.set_item(intern!(py, "type_class"), tc)?;
        Ok(d)
    }

    /// The `data_type` entry and the type class of a type.
    fn type_ref(&mut self, t: &TypeRef) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
        let py = self.py;
        Ok(match t {
            TypeRef::Atomic(e) => (
                e.map(Elementary::name).into_pyobject(py)?.into_any(),
                self.atomic(*e)?,
            ),
            TypeRef::Struct(dt) => {
                let dict = self.data_type(dt)?;
                let tc = dict
                    .get_item(intern!(py, "type_class"))?
                    .unwrap_or_else(|| py.None().into_bound(py));
                (dict.into_any(), tc)
            }
        })
    }

    /// A tag's dict.
    fn tag(&mut self, t: &TagDef) -> PyResult<Bound<'py, PyDict>> {
        let py = self.py;
        let d = PyDict::new(py);
        d.set_item(intern!(py, "tag_name"), &t.tag_name)?;
        d.set_item(intern!(py, "dim"), t.dim)?;
        d.set_item(intern!(py, "alias"), t.alias)?;
        d.set_item(intern!(py, "instance_id"), t.instance_id)?;
        d.set_item(intern!(py, "symbol_address"), t.symbol_address)?;
        d.set_item(
            intern!(py, "symbol_object_address"),
            t.symbol_object_address,
        )?;
        d.set_item(intern!(py, "software_control"), t.software_control)?;
        d.set_item(intern!(py, "external_access"), &t.external_access)?;
        d.set_item(intern!(py, "dimensions"), PyList::new(py, t.dimensions)?)?;
        if let Some(id) = t.template_instance_id {
            d.set_item(intern!(py, "template_instance_id"), id)?;
        }
        let (data_type, mut tc) = self.type_ref(&t.data_type)?;
        d.set_item(intern!(py, "data_type"), data_type)?;
        d.set_item(intern!(py, "data_type_name"), t.data_type.name())?;
        if let Some(bit) = t.bit_position {
            d.set_item(intern!(py, "bit_position"), bit)?;
        }
        d.set_item(intern!(py, "tag_type"), t.data_type.tag_type())?;
        if t.dim > 0 {
            let dims = &t.dimensions[..usize::from(t.dim).min(3)];
            let length = dims
                .iter()
                .try_fold(1usize, |n, d| n.checked_mul(*d as usize))
                .unwrap_or(usize::MAX);
            tc = self.array(length, &tc)?;
        }
        d.set_item(intern!(py, "type_class"), tc)?;
        Ok(d)
    }
}

/// The reference driver's `tags_json`: a copy of each tag dict and of the data type dicts in it, without
/// `type_class` and `_struct_members` (the other values are shared with `tags`, as there).  Within one result
/// each data type is copied once and shared by the tags and members of that type, as in `tags` (the reference
/// driver copies it again for each).
pub(crate) fn tags_json<'py>(
    py: Python<'py>,
    tags: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyDict>> {
    without_gc(py, || {
        let mut copies = HashMap::new();
        let out = PyDict::new(py);
        for (name, tag) in tags.iter() {
            let tag = tag.cast_into::<PyDict>()?;
            out.set_item(name, copy_without_classes(py, &tag, &mut copies)?)?;
        }
        Ok(out)
    })
}

/// `src` without its type classes, its `data_type` dict copied once per result (`copies`, by address).
fn copy_without_classes<'py>(
    py: Python<'py>,
    src: &Bound<'py, PyDict>,
    copies: &mut HashMap<usize, Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let type_class = intern!(py, "type_class");
    let struct_members = intern!(py, "_struct_members");
    let data_type = intern!(py, "data_type");
    let internal_tags = intern!(py, "internal_tags");
    let new = PyDict::new(py);
    for (k, v) in src.iter() {
        if let Ok(s) = k.cast::<PyString>() {
            if s.is(type_class)
                || s.is(struct_members)
                || s == "type_class"
                || s == "_struct_members"
            {
                continue;
            }
            if s.is(data_type) {
                if let Ok(dt) = v.cast::<PyDict>() {
                    let addr = dt.as_ptr() as usize;
                    let copy = match copies.get(&addr) {
                        Some(copy) => copy.clone(),
                        None => {
                            let copy = copy_without_classes(py, dt, copies)?;
                            copies.insert(addr, copy.clone());
                            copy
                        }
                    };
                    new.set_item(&k, copy)?;
                    continue;
                }
            } else if s.is(internal_tags) {
                if let Ok(members) = v.cast::<PyDict>() {
                    let copied = PyDict::new(py);
                    for (name, member) in members.iter() {
                        let member = member.cast_into::<PyDict>()?;
                        copied.set_item(name, copy_without_classes(py, &member, copies)?)?;
                    }
                    new.set_item(&k, copied)?;
                    continue;
                }
            }
        }
        new.set_item(&k, &v)?;
    }
    Ok(new)
}
