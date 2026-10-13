import re
import struct

from .cip import DataTypes, Services
from .exceptions import RequestError, ResponseError
from .logix_metadata import (
    build_description_index_request,
    build_description_request,
    decode_description_records,
    decode_description_response,
    decode_metadata_page,
)
from .packets import SendUnitDataRequestPacket


_SEGMENT = re.compile(r"([^\[\]{}.\s]+)(?:\[([0-9]+(?:,[0-9]+){0,2})\])?")


def _cache(plc):
    cache = plc._cache.setdefault("descriptions", {})
    connection = (plc._session, plc._target_cid)
    if cache.get("connection") != connection:
        cache.clear()
        cache.update(connection=connection, programs={}, members={}, records={})
    return cache


def _pages(plc, builder):
    pages = []
    offset = 0
    connection = (plc._session, plc._target_cid)
    for _ in range(1024):
        request = SendUnitDataRequestPacket(plc._sequence)
        request.add(builder(offset))
        response = plc.send(request)
        if not response:
            raise ResponseError(response.error)
        if (not plc._target_is_connected
                or connection != (plc._session, plc._target_cid)):
            raise ResponseError("Connection changed during Description read")
        page = decode_metadata_page(response.data)
        if page["first"] != (offset == 0) or page["offset"] != offset:
            raise ResponseError("Out-of-order extended description page")
        pages.append(response.data)
        if page["last"]:
            return pages
        if not page["data"]:
            raise ResponseError("Extended description continuation made no progress")
        offset += len(page["data"])
    raise ResponseError("Extended description exceeded 1024 pages")


def _value(plc, target, path, language, encoding):
    class_id, instance_id, a, b = target
    pages = _pages(plc, lambda offset: build_description_request(
        instance_id, language, offset, path=path, class_id=class_id,
        owner_context=(a, b)))
    record = decode_description_response(pages, encoding)
    if record is not None and (
            record["class_id"] != class_id or record["instance_id"] != instance_id
            or record["owner_context"] != [a, b]
            or record["path"].lower() != path.lower()
            or record["language"] != language):
        raise ResponseError("Extended description reply targets a different tag/language")
    return None if record is None else record["value"]


def _program_id(plc, name):
    cache = _cache(plc)["programs"]
    key = name.lower()
    if key not in cache:
        programs = plc._info.get("programs", {})
        program = next((key for key in programs if key.lower() == name.lower()), None)
        if program is None and plc._lazy_tags:
            symbols = plc._lazy_tag_lists.get(None)
            if symbols is None:
                symbols = {item["tag_name"]: item
                           for item in plc._get_instance_attribute_list_service()}
                plc._lazy_tag_lists[None] = symbols
            symbol = next((value for key, value in symbols.items()
                           if key.lower() == ("Program:" + name).lower()), None)
            if symbol is not None:
                programs[name] = {"instance_id": symbol["instance_id"], "routines": []}
                plc._info["programs"] = programs
                program = name
        if program is None:
            raise RequestError("Program does not exist: " + name)
        response = plc.generic_message(
            service=Services.get_attribute_list, class_code=0x6B,
            instance=programs[program]["instance_id"],
            request_data=b"\x01\x00\x0d\x00", connected=True)
        if not response:
            raise ResponseError(response.error)
        raw = response.value
        if raw[:6] != b"\x01\x00\x0d\x00\x00\x00" or len(raw) < 11:
            raise ResponseError("Invalid program reference")
        path = raw[7:]
        if len(path) != raw[6] * 2 or path[:2] != b"\x20\x68":
            raise ResponseError("Invalid program reference")
        if len(path) == 4 and path[2] == 0x24:
            instance = path[3]
        elif len(path) == 6 and path[2:4] == b"\x25\x00":
            instance = struct.unpack_from("<H", path, 4)[0]
        elif len(path) == 8 and path[2:4] == b"\x26\x00":
            instance = struct.unpack_from("<I", path, 4)[0]
        else:
            raise ResponseError("Invalid program reference")
        if not 1 <= instance <= 0xFFFF:
            raise ResponseError("Unsupported program reference")
        cache[key] = instance
    return cache[key]


def _template_id(plc, definition):
    if "template_instance_id" in definition:
        return definition["template_instance_id"]
    for instance, data in plc._cache["id:udt"].items():
        if data is definition.get("data_type"):
            return instance
    raise RequestError("Missing member type definition")


def _member_ids(plc, instance, data):
    cache = _cache(plc)["members"]
    if instance not in cache:
        template = data["template"]
        names = list(data["internal_tags"])
        count = template["member_count"]
        if len(names) != count:
            raise ResponseError("Incomplete member definitions")
        if instance < 0x100 or instance > 0xEFF:
            identifiers = list(range(1, count + 1))
        else:
            raw = plc._read_template(instance, template["object_definition_size"])
            cursor = count * 8
            try:
                for _ in range(count + 1):
                    cursor = raw.index(b"\x00", cursor) + 1
            except ValueError as error:
                raise ResponseError("Incomplete member definitions") from error
            cursor = (cursor + 3) & ~3
            required = cursor + count * 2
            if required > len(raw):
                missing = required - len(raw)
                if missing > 21:
                    raise ResponseError("Incomplete member identifiers")
                response = plc.generic_message(
                    service=Services.read_tag, class_code=0x6C, instance=instance,
                    request_data=struct.pack("<IH", len(raw), missing), connected=True)
                if not response:
                    raise ResponseError(response.error)
                if len(response.value) != missing:
                    raise ResponseError("Incomplete member identifiers")
                raw += response.value
            identifiers = struct.unpack_from("<{}H".format(count), raw, cursor)
        cache[instance] = dict(zip(names, identifiers))
    return cache[instance]


def _type_value(plc, instance, member_id, language, encoding):
    cache = _cache(plc)["records"]
    if language not in cache:
        cache[language] = decode_description_records(_pages(
            plc, lambda offset: build_description_index_request(language, offset)), None)
    matches = [record for record in cache[language]
               if record["class_id"] == 0x6C
               and record["instance_id"] & 0xFFFF == instance
               and record["owner_context"] == [member_id, 0]
               and record["path"] == "" and record["language"] == language
               and record["kind"] == 1]
    if len(matches) > 1:
        raise ResponseError("Ambiguous member description")
    return None if not matches else matches[0]["value"].decode(encoding)


def _indices(definition, indices):
    if indices is None:
        return ""
    values = [int(value) for value in indices.split(",")]
    dimensions = definition.get("dimensions")
    if dimensions is not None:
        dimensions = dimensions[:definition.get("dim", len(values))]
    else:
        dimensions = [definition.get("array", 0)]
    if definition.get("data_type_name") == "DWORD" and dimensions:
        dimensions = list(dimensions)
        dimensions[-1] *= 32
    if (len(values) != len(dimensions) or any(
            dimension <= 0 or not 0 <= value < dimension
            for value, dimension in zip(values, dimensions))):
        raise RequestError("Array index is outside the tag's dimensions")
    return "[{}]".format(",".join(str(value) for value in values))


def read_description(plc, tag_name, language, encoding):
    if not isinstance(tag_name, str) or not tag_name or "{" in tag_name or "}" in tag_name:
        raise RequestError("Specify a tag, member, or array element")
    program = None
    body = tag_name
    if tag_name[:8].lower() == "program:":
        scope, separator, body = tag_name.partition(".")
        program = scope[8:]
        if not separator or not program:
            raise RequestError("Specify a program tag")
    parts = body.split(".")
    parsed = [_SEGMENT.fullmatch(part) for part in parts]
    if not all(parsed):
        raise RequestError("Invalid tag address")
    root = parsed[0].group(1)
    if program is not None:
        root = "Program:" + program + "." + root
    definition = plc.get_tag_info(root)
    if definition is None:
        raise RequestError("Tag does not exist: " + root)
    steps = [(definition, parsed[0].group(2), None)]
    current = definition
    for index, match in enumerate(parsed[1:], 1):
        name, indices = match.groups()
        if name.isdigit():
            data_type = current.get("data_type_name")
            if (index != len(parsed) - 1 or indices is not None
                    or data_type not in {"SINT", "INT", "DINT", "LINT", "USINT",
                                         "UINT", "UDINT", "ULINT", "DWORD"}
                    or not 0 <= int(name) < DataTypes.get(data_type).size * 8):
                raise RequestError("Invalid tag bit")
            steps.append((current, None, int(name)))
            continue
        data = current.get("data_type")
        members = data.get("internal_tags", {}) if isinstance(data, dict) else {}
        member = next((key for key in members if key.lower() == name.lower()), None)
        if member is None:
            raise RequestError("Tag doesn't exist - " + name)
        steps.append((members[member], indices, (current, member)))
        current = members[member]
    for index, (data, indices, member) in enumerate(steps):
        _indices(data, indices)
        dimensions = data.get("dimensions", [data.get("array", 0)])
        if (indices is None and any(dimensions) and index < len(steps) - 1):
            raise RequestError("Select an array element before a member or bit")
    target = (0x6B, definition["instance_id"], 0, 0)
    if program is not None:
        target = (0x68, (0x6B << 16) | _program_id(plc, program),
                  definition["instance_id"], 0)
    path = ""
    candidates = [(path, None)]
    for data, indices, member in steps:
        if isinstance(member, int):
            path += "." + str(member)
            candidates.append((path, None))
        elif member is not None:
            parent, name = member
            instance = _template_id(plc, parent)
            identifier = _member_ids(plc, instance, parent["data_type"])[name]
            path += ".!{:04X}{:04X}".format(instance, identifier)
            candidates.append((path, (instance, identifier)))
        suffix = _indices(data, indices)
        if suffix:
            path += suffix
            candidates.append((path, None))
    for path, member in reversed(candidates):
        value = _value(plc, target, path, language, encoding)
        if value is not None:
            return value
        if member is not None:
            value = _type_value(plc, *member, language, encoding)
            if value is not None:
                return value
    return None
