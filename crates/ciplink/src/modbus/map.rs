//! The map file: one CSV row per tag giving its name, area, address, type and description. The CSV reader is
//! hand written (RFC 4180 quoting) to keep the crate free of a CSV dependency.

use std::path::Path;

use indexmap::IndexMap;

use super::address::{Address, Area, DataType, TYPE_NAMES, WordOrder, size_of};
use crate::{Error, Result};

/// The tags of a map file, in file order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TagMap {
    tags: IndexMap<String, MapTag>,
}

/// One row of a map file.
#[derive(Clone, Debug, PartialEq)]
pub struct MapTag {
    /// The tag name, as written in the file.
    pub name: String,
    /// The table.
    pub area: Area,
    /// 0-based protocol address of the first register or bit.
    pub address: u16,
    /// The bit of a `bool` in a holding or input register.
    pub bit: Option<u8>,
    /// The type.
    pub data_type: DataType,
    /// Elements; a string's length in characters.
    pub count: u16,
    /// None: the driver's word order.
    pub order: Option<WordOrder>,
    /// None: the path's unit.
    pub unit: Option<u8>,
    /// Read value = raw x scale + offset.
    pub scale: Option<f64>,
    /// Added after the scale.
    pub offset: Option<f64>,
    /// Engineering units (`rpm`).
    pub units: String,
    /// Free text.
    pub description: String,
    /// False for read-only rows (always for discrete inputs and input registers).
    pub writable: bool,
}

impl MapTag {
    /// The CIP type name a read reports: `LREAL` when scaled, else the type's (`REAL` for float32).
    pub fn type_name(&self) -> &'static str {
        if self.scale.is_some() || self.offset.is_some() {
            "LREAL"
        } else {
            self.data_type.cip_name()
        }
    }
}

impl TagMap {
    /// Reads a map file; errors name the file and line.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = path.file_name().map_or_else(
            || path.display().to_string(),
            |f| f.to_string_lossy().into_owned(),
        );
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::request(format!("cannot read map file {}: {e}", path.display())))?;
        Self::from_csv(&text).map_err(|e| Error::request(format!("{file} {e}")))
    }

    /// Parses map CSV text (errors name the line).
    pub fn from_csv(text: &str) -> Result<Self> {
        parse(text).map_err(Error::request)
    }

    /// The tag of `name`, ignoring case.
    pub fn get(&self, name: &str) -> Option<&MapTag> {
        self.tags.get(&name.to_ascii_lowercase())
    }

    /// Every tag, in file order.
    pub fn tags(&self) -> impl Iterator<Item = &MapTag> {
        self.tags.values()
    }

    /// The number of tags.
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// True without tags.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

/// One CSV record and the line it starts on.
struct Record {
    line: usize,
    fields: Vec<String>,
}

/// The separator: `;` when the header line has a semicolon and no comma, else `,`.
fn separator(text: &str) -> char {
    let header = text
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .unwrap_or_default();
    if !header.contains(',') && header.contains(';') {
        ';'
    } else {
        ','
    }
}

/// Splits `text` into records; `#` lines and blank lines are skipped.
fn records(text: &str, sep: char) -> std::result::Result<Vec<Record>, String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    let mut line = 1;
    while let Some(&first) = chars.peek() {
        if first == '#' {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            line += 1;
            continue;
        }
        let start = line;
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        loop {
            match chars.next() {
                None => break,
                Some('"') if field.trim().is_empty() && !quoted => {
                    field.clear();
                    quoted = true;
                    loop {
                        match chars.next() {
                            None => {
                                return Err(format!("line {start}: a quoted field is not closed"));
                            }
                            Some('"') if chars.peek() == Some(&'"') => {
                                chars.next();
                                field.push('"');
                            }
                            Some('"') => break,
                            Some(c) => {
                                if c == '\n' {
                                    line += 1;
                                }
                                field.push(c);
                            }
                        }
                    }
                }
                Some(c) if c == sep => {
                    fields.push(finish(&mut field, quoted));
                    quoted = false;
                }
                Some('\r') if chars.peek() == Some(&'\n') => {}
                Some('\n') => {
                    line += 1;
                    break;
                }
                Some(c) if quoted => {
                    if !c.is_whitespace() {
                        return Err(format!("line {line}: text after a closing quote"));
                    }
                }
                Some(c) => field.push(c),
            }
        }
        fields.push(finish(&mut field, quoted));
        if fields.iter().any(|f| !f.is_empty()) {
            out.push(Record {
                line: start,
                fields,
            });
        }
    }
    Ok(out)
}

fn finish(field: &mut String, quoted: bool) -> String {
    let value = std::mem::take(field);
    if quoted {
        value
    } else {
        value.trim().to_owned()
    }
}

const COLUMNS: [&str; 12] = [
    "name",
    "area",
    "address",
    "type",
    "count",
    "order",
    "unit",
    "scale",
    "offset",
    "units",
    "description",
    "writable",
];

fn parse(text: &str) -> std::result::Result<TagMap, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut records = records(text, separator(text))?.into_iter();
    let Some(header) = records.next() else {
        return Err("the map has no header line".into());
    };
    // the index of each known column, by its header name
    let mut index: [Option<usize>; COLUMNS.len()] = [None; COLUMNS.len()];
    for (i, name) in header.fields.iter().enumerate() {
        if let Some(c) = COLUMNS
            .iter()
            .position(|c| c.eq_ignore_ascii_case(name.trim()))
        {
            index[c] = Some(i);
        }
    }
    // the first four columns are required
    for (c, name) in COLUMNS[..4].iter().enumerate() {
        if index[c].is_none() {
            return Err(format!("line {}: missing column '{name}'", header.line));
        }
    }
    let mut map = TagMap::default();
    for record in records {
        let get = |column: &str| -> &str {
            COLUMNS
                .iter()
                .position(|c| *c == column)
                .and_then(|c| index[c])
                .and_then(|i| record.fields.get(i))
                .map_or("", String::as_str)
        };
        let tag = row(&get, &map).map_err(|e| format!("line {}: {e}", record.line))?;
        map.tags.insert(tag.name.to_ascii_lowercase(), tag);
    }
    Ok(map)
}

fn valid_name(name: &str) -> bool {
    name.split('.').all(|part| {
        let mut chars = part.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn required<'a>(
    get: &impl Fn(&str) -> &'a str,
    column: &str,
) -> std::result::Result<&'a str, String> {
    match get(column) {
        "" => Err(format!("{column} is empty")),
        value => Ok(value),
    }
}

fn number<T: std::str::FromStr>(
    column: &str,
    value: &str,
    range: &str,
) -> std::result::Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{column} '{value}' is not a number in {range}"))
}

fn optional_f64(column: &str, value: &str) -> std::result::Result<Option<f64>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    match value.parse::<f64>() {
        Ok(v) if v.is_finite() => Ok(Some(v)),
        _ => Err(format!("{column} '{value}' is not a number")),
    }
}

/// One row, checked against every rule.
fn row<'a>(get: &impl Fn(&str) -> &'a str, map: &TagMap) -> std::result::Result<MapTag, String> {
    let name = required(get, "name")?;
    if !valid_name(name) {
        return Err(format!(
            "name '{name}' must be letters, digits and _, not starting with a digit (dots between parts)"
        ));
    }
    if Address::parse(name).is_ok() {
        return Err(format!("name '{name}' is a plain address"));
    }
    if map.get(name).is_some() {
        return Err(format!("name '{name}' is used twice (names ignore case)"));
    }
    let area_text = required(get, "area")?;
    let area = Area::parse(area_text).ok_or_else(|| {
        format!("area '{area_text}' is not one of coil, discrete, holding, input")
    })?;
    let type_text = required(get, "type")?;
    let data_type = DataType::parse(type_text)
        .ok_or_else(|| format!("type '{type_text}' is not one of {TYPE_NAMES}"))?;
    let address_text = required(get, "address")?;
    let (address, bit) = match address_text.split_once('.') {
        Some((register, bit)) => {
            let bit: u8 = number("address", bit, "0..15")?;
            if bit > 15 {
                return Err(format!("address '{address_text}': bit {bit} is not 0..15"));
            }
            (register, Some(bit))
        }
        None => (address_text, None),
    };
    let address: u16 = number("address", address, "0..65535")?;
    let count = match get("count") {
        "" if data_type == DataType::String => {
            return Err("count is required for a string (its length in characters)".into());
        }
        "" => 1,
        text => match number::<u16>("count", text, "1..65535")? {
            0 => return Err("count must be at least 1".into()),
            n => n,
        },
    };
    match (data_type, area.is_bits(), bit) {
        (DataType::Bool, true, Some(_)) => {
            return Err(format!("address '{address_text}': a {area} has no bit"));
        }
        (DataType::Bool, false, None) => {
            return Err(format!(
                "address '{address_text}': a bool in a {area} register needs a bit (register.bit)"
            ));
        }
        (DataType::Bool, false, Some(_)) if count != 1 => {
            return Err("count must be 1 for a bit of a register".into());
        }
        (DataType::Bool, ..) => {}
        (_, true, _) => return Err(format!("type {data_type} is not valid in a {area}")),
        (_, false, Some(_)) => {
            return Err(format!("address '{address_text}': only a bool has a bit"));
        }
        (_, false, None) => {}
    }
    let order = match get("order") {
        "" => None,
        text => Some(
            WordOrder::parse(text)
                .ok_or_else(|| format!("order '{text}' is not one of ABCD, CDAB, BADC, DCBA"))?,
        ),
    };
    let unit = match get("unit") {
        "" => None,
        text => Some(number::<u8>("unit", text, "0..255")?),
    };
    let scale = optional_f64("scale", get("scale"))?;
    let offset = optional_f64("offset", get("offset"))?;
    if (scale.is_some() || offset.is_some()) && !data_type.is_numeric() {
        return Err(format!("scale and offset are not valid on a {data_type}"));
    }
    let writable = match get("writable").to_ascii_lowercase().as_str() {
        "" => area.is_writable(),
        "true" | "yes" | "1" => {
            if !area.is_writable() {
                return Err(format!("writable is true on a read-only {area}"));
            }
            true
        }
        "false" | "no" | "0" => false,
        _ => {
            return Err(format!(
                "writable '{}' is not true or false",
                get("writable")
            ));
        }
    };
    let size = size_of(area, bit, data_type, count).ok_or("count is too large")?;
    if u32::from(address) + u32::from(size.max(1)) - 1 > 65535 {
        return Err(format!(
            "the tag runs past address 65535 ({address} + {size})"
        ));
    }
    Ok(MapTag {
        name: name.to_owned(),
        area,
        address,
        bit,
        data_type,
        count,
        order,
        unit,
        scale,
        offset,
        units: get("units").to_owned(),
        description: get("description").to_owned(),
        writable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../../tools/sim/example_modbus_map.csv");

    fn error(text: &str) -> String {
        match TagMap::from_csv(text) {
            Err(Error::Request { message, .. }) => message,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn example_map_parses() {
        let map = TagMap::from_csv(EXAMPLE).expect("example");
        assert_eq!(map.len(), 10);
        let names: Vec<&str> = map.tags().map(|t| t.name.as_str()).collect();
        assert_eq!(names[0], "Pump1_Speed");
        assert_eq!(names[9], "Valve2_Open");
        let speed = map.get("pump1_speed").expect("speed");
        assert_eq!(
            (speed.area, speed.address, speed.data_type, speed.order),
            (Area::Holding, 0, DataType::Float32, Some(WordOrder::Cdab))
        );
        assert_eq!((speed.units.as_str(), speed.writable), ("rpm", true));
        assert_eq!(
            map.get("Pump1_Fault").expect("fault").description,
            "Pump 1 fault, any cause"
        );
        assert!(!map.get("Pump1_Fault").expect("fault").writable);
        let temp = map.get("Tank_Temp").expect("temp");
        assert_eq!((temp.scale, temp.offset), (Some(0.1), Some(-40.0)));
        assert_eq!(temp.type_name(), "LREAL");
        assert_eq!(map.get("Totals").expect("totals").count, 4);
        assert_eq!(map.get("Recipe").expect("recipe").count, 16);
        assert!(!map.get("Drive_Status").expect("status").writable);
        let horn = map.get("Horn").expect("horn");
        assert_eq!((horn.address, horn.bit), (301, Some(4)));
        assert_eq!(map.get("Valve2_Open").expect("valve").unit, Some(2));
    }

    #[test]
    fn quoted_fields_with_commas_quotes_and_newlines() {
        let map = TagMap::from_csv(
            "name,area,address,type,description\n\
             A,coil,0,bool,\"one, two\"\n\
             B,coil,1,bool,\"say \"\"hi\"\"\"\n\
             C,coil,2,bool,\"line one\r\nline two\"\n\
             D,coil,3,bool, \"padded\" \n\
             E,coil,4,bool,\n",
        )
        .expect("map");
        let d = |n: &str| map.get(n).expect(n).description.clone();
        assert_eq!(d("A"), "one, two");
        assert_eq!(d("B"), "say \"hi\"");
        assert_eq!(d("C"), "line one\r\nline two");
        assert_eq!(d("D"), "padded");
        assert_eq!(d("E"), "");
        // the line after a field with a line break is counted
        let message =
            error("name,area,address,type,description\nA,coil,0,bool,\"x\ny\"\nB,coil,0,nope,\n");
        assert!(message.starts_with("line 4:"), "{message}");
        assert!(error("name,area,address,type\nA,coil,0,\"bool").contains("not closed"));
        assert!(
            error("name,area,address,type\nA,coil,0,\"bool\"x").contains("after a closing quote")
        );
    }

    #[test]
    fn semicolon_files() {
        let map = TagMap::from_csv(
            "name;area;address;type;description\nA;holding;0;float32;\"a;b, c\"\n",
        )
        .expect("map");
        assert_eq!(map.get("A").expect("A").description, "a;b, c");
    }

    #[test]
    fn bom_comments_blank_lines_and_extra_columns() {
        let map = TagMap::from_csv(
            "\u{feff}# a comment\n\n  Type , NAME,Notes,area,ADDRESS\r\n\r\nint16,X,anything,ir,7\r\n# more\r\n   \r\n",
        )
        .expect("map");
        assert_eq!(map.len(), 1);
        let x = map.get("x").expect("x");
        assert_eq!(
            (x.area, x.address, x.data_type, x.writable),
            (Area::Input, 7, DataType::Int16, false)
        );
    }

    #[test]
    fn errors_name_line_and_column() {
        let head = "name,area,address,type,count,order,unit,scale,offset,writable\n";
        let cases = [
            (
                "X,holding,0,flaot32,,,,,,",
                "line 2: type 'flaot32' is not one of bool, int16",
            ),
            (",holding,0,int16,,,,,,", "line 2: name is empty"),
            ("1X,holding,0,int16,,,,,,", "line 2: name '1X'"),
            ("A.3,holding,0,int16,,,,,,", "line 2: name 'A.3'"),
            ("X,register,0,int16,,,,,,", "line 2: area 'register'"),
            ("X,holding,65536,int16,,,,,,", "line 2: address '65536'"),
            ("X,holding,,int16,,,,,,", "line 2: address is empty"),
            ("X,holding,0,string,,,,,,", "line 2: count is required"),
            (
                "X,holding,0,int16,0,,,,,",
                "line 2: count must be at least 1",
            ),
            (
                "X,coil,0.1,bool,,,,,,",
                "line 2: address '0.1': a coil has no bit",
            ),
            (
                "X,holding,0,bool,,,,,,",
                "line 2: address '0': a bool in a holding register needs a bit",
            ),
            (
                "X,holding,0.16,bool,,,,,,",
                "line 2: address '0.16': bit 16",
            ),
            ("X,holding,0.1,bool,2,,,,,", "line 2: count must be 1"),
            (
                "X,coil,0,int16,,,,,,",
                "line 2: type int16 is not valid in a coil",
            ),
            (
                "X,holding,0.1,int16,,,,,,",
                "line 2: address '0.1': only a bool",
            ),
            ("X,holding,0,int32,,ACBD,,,,", "line 2: order 'ACBD'"),
            ("X,holding,0,int16,,,256,,,", "line 2: unit '256'"),
            ("X,holding,0,int16,,,,x,,", "line 2: scale 'x'"),
            ("X,holding,0,int16,,,,,y,", "line 2: offset 'y'"),
            (
                "X,holding,0,string,4,,,2,,",
                "line 2: scale and offset are not valid on a string",
            ),
            (
                "X,coil,0,bool,,,,,1,",
                "line 2: scale and offset are not valid on a bool",
            ),
            (
                "X,input,0,int16,,,,,,true",
                "line 2: writable is true on a read-only input",
            ),
            ("X,holding,0,int16,,,,,,maybe", "line 2: writable 'maybe'"),
            (
                "X,holding,65535,int32,,,,,,",
                "line 2: the tag runs past address 65535",
            ),
            (
                "X,coil,65535,bool,2,,,,,",
                "line 2: the tag runs past address 65535",
            ),
        ];
        for (row, expect) in cases {
            let message = error(&format!("{head}{row}\n"));
            assert!(message.starts_with(expect), "{row}: {message}");
        }
        assert_eq!(
            error("name,area,type\nX,holding,int16\n"),
            "line 1: missing column 'address'"
        );
        assert_eq!(error("# only a comment\n"), "the map has no header line");
    }

    #[test]
    fn name_that_is_an_address_is_refused() {
        let message = error("name,area,address,type\nhr100,holding,0,int16\n");
        assert_eq!(message, "line 2: name 'hr100' is a plain address");
        assert!(TagMap::from_csv("name,area,address,type\nhr100x,holding,0,int16\n").is_ok());
    }

    #[test]
    fn duplicate_names_ignoring_case() {
        let message =
            error("name,area,address,type\nPump,holding,0,int16\n\nPUMP,holding,1,int16\n");
        assert_eq!(
            message,
            "line 4: name 'PUMP' is used twice (names ignore case)"
        );
    }

    #[test]
    fn load_names_the_file() {
        let dir = std::env::temp_dir().join(format!("ciplink-map-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("pumps.csv");
        std::fs::write(&path, "name,area,address,type\nX,holding,0,flaot32\n").expect("write");
        let message = TagMap::load(&path).expect_err("bad type").to_string();
        assert!(
            message.starts_with("pumps.csv line 2: type 'flaot32'"),
            "{message}"
        );
        std::fs::write(&path, EXAMPLE).expect("write");
        assert_eq!(TagMap::load(&path).expect("example").len(), 10);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(TagMap::load(dir.join("missing.csv")).is_err());
    }
}
