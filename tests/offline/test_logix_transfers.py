"""Exercise public transfers with controller replies and realistic packet limits."""
import struct
import threading
from unittest import mock

import pytest

from pycomm3 import Array, DINT, DWORD, INT, SINT, CommError, LogixDriver, RequestError
from pycomm3.cip_driver import CIPDriver
from pycomm3.const import BASE_TAG_BIT
from pycomm3.packets import (
    MultiServiceRequestPacket, ReadModifyWriteRequestPacket,
    ReadTagFragmentedRequestPacket, ReadTagRequestPacket,
    WriteTagRequestPacket,
)
from pycomm3.util import get_array_index


def definition(name, dtype=DINT, length=None):
    return {
        "tag_name": name, "tag_type": "atomic", "data_type": dtype.__name__,
        "data_type_name": dtype.__name__, "instance_id": None,
        "dim": 1 if length else 0, "dimensions": [length or 0, 0, 0],
        "type_class": Array(length, dtype) if length else dtype,
    }


def driver(*definitions, connection_size=500, micro800=False):
    plc = LogixDriver("127.0.0.1", init_tags=False, connection_size=connection_size)
    plc._target_is_connected = plc._connection_opened = True
    plc._micro800 = micro800
    plc._tags = {info["tag_name"]: info for info in definitions}
    return plc


def reply(request, data=b"", status=0, extended=b""):
    service = b"\x0a" if isinstance(request, MultiServiceRequestPacket) else request.tag_service
    raw = bytes(46) + bytes([service[0] | 0x80, 0, status, len(extended) // 2]) + extended + data
    return request.response_class(request, raw)


class Controller:
    def __init__(self, values=None, fail=None):
        self.values = values or {}
        self.fail = fail or {}
        self.sent = []

    def send(self, request):
        self.sent.append(request)
        if isinstance(request, MultiServiceRequestPacket):
            responses = [self.send(req).raw[46:] for req in request.requests]
            offset = 2 + 2 * len(responses)
            offsets = []
            for response in responses:
                offsets.append(struct.pack("<H", offset))
                offset += len(response)
            return reply(request, struct.pack("<H", len(responses)) + b"".join(offsets + responses))
        if request.tag in self.fail:
            return reply(request, status=self.fail[request.tag])
        if isinstance(request, ReadModifyWriteRequestPacket):
            self.values[request.tag] = ((self.values[request.tag] | request._or_mask)
                                        & request._and_mask) & 0xffffffff
            return reply(request)
        if isinstance(request, WriteTagRequestPacket):
            return reply(request)
        dtype = request.tag_info["type_class"]
        element = dtype.element_type if hasattr(dtype, "element_type") else dtype
        if element == DWORD:
            base, index = get_array_index(request.tag)
            data = b"".join(struct.pack("<I", self.values[f"{base}[{i}]"])
                            for i in range(index or 0, (index or 0) + request.elements))
        else:
            values = self.values.get(request.tag, [12] * request.elements)
            if not isinstance(values, list):
                values = [values]
            data = b"".join(element.encode(value) for value in values[:request.elements])
        return reply(request, struct.pack("<H", element.code) + data)


@pytest.mark.parametrize("size", [50, 100, 500, 4000])
def test_read_batches_bound_outgoing_and_incoming_messages(size):
    tags = ["long_symbol_" + str(i).zfill(4) + "x" * 10 for i in range(20)]
    plc = driver(*(definition(tag) for tag in tags), connection_size=size)
    controller = Controller()
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        results = plc.read(*tags)
    assert [result.tag for result in results] == tags
    assert all(result.value == 12 and result.error is None for result in results)
    for request in controller.sent:
        assert len(request.build_message()) <= size
        if isinstance(request, MultiServiceRequestPacket):
            assert 8 + len(request.requests) * 12 <= size
            assert request.build_message() == request.build_message()


def test_read_that_fits_alone_is_not_lost_at_batch_boundary():
    plc = driver(definition("a", DINT, 122), definition("b"))
    controller = Controller()
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        results = plc.read("a{122}", "b")
    assert all(results)
    assert len(results[0].value) == 122
    assert isinstance(controller.sent[0], ReadTagRequestPacket)
    assert not isinstance(controller.sent[0], ReadTagFragmentedRequestPacket)


@pytest.mark.parametrize("start,count", [(1, 2), (30, 5), (35, 40), (63, 2)])
@pytest.mark.parametrize("micro800", [False, True])
def test_bool_slices_preserve_every_unrequested_bit(start, count, micro800):
    plc = driver(definition("flags", DWORD, 4), micro800=micro800)
    original = {f"flags[{i}]": 0xa5a5a5a5 for i in range(4)}
    controller = Controller(original.copy())
    values = [i % 3 == 0 for i in range(count)]
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        result = plc.write(f"flags[{start}]{{{count}}}", values)
        read_result = plc.read(f"flags[{start}]{{{count}}}")
    assert result.error is None and result.type == f"BOOL[{count}]"
    assert read_result.value == values
    for bit in range(128):
        expected_bit = values[bit - start] if start <= bit < start + count else bool(
            original[f"flags[{bit // 32}]"] & (1 << (bit % 32)))
        assert bool(controller.values[f"flags[{bit // 32}]"] & (1 << (bit % 32))) == expected_bit
    reads = [request for request in controller.sent if isinstance(request, ReadTagRequestPacket)]
    assert reads[-1].tag == f"flags[{start // 32}]"
    assert reads[-1].elements == (start % 32 + count + 31) // 32


def test_bool_slice_reports_failure_in_any_word():
    plc = driver(definition("flags", DWORD, 3))
    controller = Controller({"flags[0]": 0, "flags[1]": 0}, fail={"flags[0]": 5})
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        result = plc.write("flags[31]{2}", [True, True])
    assert not result and result.error


def test_bool_slice_with_insufficient_values_sends_nothing():
    plc = driver(definition("flags", DWORD, 3))
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.write("flags[30]{5}", [True])
    assert not result and result.error
    send.assert_not_called()


@pytest.mark.parametrize("dtype,bit", [(SINT, 8), (INT, 16), (DINT, 32)])
def test_bit_access_outside_integer_width_sends_nothing(dtype, bit):
    plc = driver(definition("number", dtype))
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.write(f"number.{bit}", True)
    assert not result
    send.assert_not_called()


def test_integer_bit_write_accepts_last_valid_bit():
    plc = driver(definition("number", DINT))
    controller = Controller({"number": 0})
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        result = plc.write("number.31", True)
    assert result and controller.values["number"] == 0x80000000


def test_bit_write_on_multidimensional_array_element():
    plc = driver(dict(definition("grid", DINT, 6), dim=2, dimensions=[2, 3, 0]))
    controller = Controller({"grid[1,2]": 0})
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        result = plc.write("grid[1,2].5", True)
    assert result and controller.values["grid[1,2]"] == 1 << 5


def test_aligned_bool_arrays_keep_full_word_write():
    plc = driver(definition("flags", DWORD, 3))
    values = [True, False] * 32
    controller = Controller()
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        result = plc.write("flags[32]{64}", values)
    assert result
    request = controller.sent[0]
    assert isinstance(request, WriteTagRequestPacket)
    assert request.tag == "flags[1]" and request.elements == 2
    assert len(request.value) == 8


def test_single_write_counts_payload_only_once():
    plc = driver(definition("numbers", DINT, 120))
    controller = Controller()
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        result = plc.write("numbers{100}", list(range(100)))
    assert result
    assert type(controller.sent[0]) is WriteTagRequestPacket
    assert len(controller.sent[0].message) <= plc.connection_size


def test_multi_service_transport_error_returns_an_error_for_each_tag():
    plc = driver(definition("a"), definition("b"))
    with mock.patch.object(CIPDriver, "send", side_effect=RequestError("request failed")):
        results = plc.read("a", "b")
    assert len(results) == 2 and all(result.error == "request failed" for result in results)


@pytest.mark.parametrize("payload", [b"", b"\x01\x00", b"\x02\x00\xff\xff\xff\xff"])
def test_malformed_multi_service_replies_do_not_lose_tags(payload):
    plc = driver(definition("a"), definition("b"))
    with mock.patch.object(CIPDriver, "send", side_effect=lambda req: reply(req, payload)):
        results = plc.read("a", "b")
    assert [result.tag for result in results] == ["a", "b"]
    assert all(result.error and "multi-service" in result.error for result in results)


def test_embedded_error_does_not_hide_a_successful_service():
    plc = driver(definition("a"), definition("b"))
    controller = Controller(fail={"a": 5})
    def send(request):
        response = controller.send(request)
        raw = bytearray(response.raw)
        raw[48] = 0x1e
        return request.response_class(request, bytes(raw))
    with mock.patch.object(CIPDriver, "send", side_effect=send):
        results = plc.read("a", "b")
    assert results[0].error and results[1].value == 12 and results[1].error is None


def test_extended_status_is_skipped_before_decoding_value():
    plc = driver(definition("a"))
    with mock.patch.object(CIPDriver, "send", side_effect=lambda req: reply(
            req, b"\xc4\x00" + DINT.encode(42), extended=b"\x00\x00")):
        result = plc.read("a")
    assert result.value == 42 and result.error is None


def test_partial_regular_read_falls_back_to_fragmented_service():
    plc = driver(definition("numbers", DINT, 3))
    sent = []
    data = b"".join(DINT.encode(i) for i in [1, 2, 3])
    def send(request):
        sent.append(request)
        if type(request) is ReadTagRequestPacket:
            return reply(request, b"\xc4\x00" + data[:4], status=6)
        begin = request.offset
        end = min(begin + 8, len(data))
        return reply(request, b"\xc4\x00" + data[begin:end], status=6 if end < len(data) else 0)
    with mock.patch.object(CIPDriver, "send", side_effect=send):
        result = plc.read("numbers{3}")
    assert result.value == [1, 2, 3]
    assert [req.offset for req in sent if isinstance(req, ReadTagFragmentedRequestPacket)] == [0, 8]


def test_fragmented_read_without_progress_stops():
    plc = driver(definition("numbers", DINT, 200))
    with mock.patch.object(CIPDriver, "send", side_effect=lambda req: reply(req, b"\xc4\x00", 6)) as send:
        result = plc.read("numbers{200}")
    assert not result and result.error
    assert send.call_count == 1


def test_fragmented_write_stops_after_first_rejected_fragment():
    plc = driver(definition("numbers", DINT, 300))
    with mock.patch.object(CIPDriver, "send", side_effect=lambda req: reply(req, status=5)) as send:
        result = plc.write("numbers{300}", list(range(300)))
    assert not result and result.error
    assert send.call_count == 1


def test_fragmented_write_rejects_header_larger_than_connection():
    plc = driver(definition("very_long_symbol", DINT, 2), connection_size=10)
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.write("very_long_symbol{2}", [1, 2])
    assert not result and result.error
    send.assert_not_called()


def test_large_array_read_combines_service_chunks_from_nonzero_index():
    plc = driver(definition("numbers", SINT, 80000), connection_size=4000)
    observed = []
    def send(request):
        observed.append((request.tag, request.elements, request.offset))
        base, start = get_array_index(request.tag)
        length = request.elements
        end = min(request.offset + 3000, length)
        data = bytes((start + i) % 100 for i in range(request.offset, end))
        return reply(request, b"\xc2\x00" + data, status=6 if end < length else 0)
    with mock.patch.object(CIPDriver, "send", side_effect=send):
        result = plc.read("numbers[10]{70000}")
    assert result.error is None and result.type == "SINT[70000]"
    assert result.value == [(10 + i) % 100 for i in range(70000)]
    assert {tag for tag, _, _ in observed} == {"numbers[10]", "numbers[65545]"}
    assert all(count <= 65535 for _, count, _ in observed)


def test_large_array_write_splits_value_by_relative_offset():
    plc = driver(definition("numbers", SINT, 80000), connection_size=4000)
    values = [i % 100 for i in range(70000)]
    reconstructed = {}
    def send(request):
        assert request.elements <= 65535
        reconstructed.setdefault(request.tag, bytearray()).extend(request.value)
        assert len(request.build_message()) <= plc.connection_size
        return reply(request)
    with mock.patch.object(CIPDriver, "send", side_effect=send):
        result = plc.write("numbers[10]{70000}", values)
    assert result and result.type == "SINT[70000]"
    assert bytes(reconstructed["numbers[10]"]) == bytes(values[:65535])
    assert bytes(reconstructed["numbers[65545]"]) == bytes(values[65535:])


def raw_tag(name, dtype=DINT, length=0, instance=1):
    return {
        "tag_name": name, "instance_id": instance,
        "symbol_type": dtype.code | (0x2000 if length else 0),
        "software_control": BASE_TAG_BIT, "dimensions": [length, 0, 0],
        "symbol_address": 0, "symbol_object_address": 0,
        "external_access": "Read/Write",
    }


def test_lazy_mode_defers_upload_and_caches_scope_definitions():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    identity = {"product_name": "1756-L85", "revision": {"major": 32}}
    with mock.patch.object(CIPDriver, "open", return_value=True), \
            mock.patch.object(plc, "_list_identity", return_value=identity), \
            mock.patch.object(plc, "get_plc_info", return_value=identity), \
            mock.patch.object(plc, "get_plc_name"), \
            mock.patch.object(plc, "get_tag_list") as upload:
        plc.open()
    upload.assert_not_called()
    plc._target_is_connected = True
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=[
            raw_tag("a"), raw_tag("b", length=10)]) as inventory:
        assert plc.get_tag_info("a")["type_class"] is DINT
        assert set(plc.tags) == {"a"}
        assert plc.get_tag_info("b[2]")["dimensions"] == [10, 0, 0]
        plc.get_tag_info("a")
    inventory.assert_called_once_with(None)


def test_lazy_program_scope_does_not_upload_unrelated_programs():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=[raw_tag("a")]) as inventory:
        assert plc.get_tag_info("Program:Main.a")["tag_name"] == "Program:Main.a"
    inventory.assert_called_once_with("Main")


def test_lazy_mode_reports_missing_tag_and_keeps_valid_tag():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    controller = Controller()
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=[raw_tag("a")]), \
            mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        results = plc.read("missing", "a")
    assert results[0].error == "Tag doesn't exist - missing" and results[1].value == 12  # same as eager mode


def test_lazy_loads_from_two_threads_do_not_fail_each_other():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    entered, release = threading.Event(), {0x101: threading.Event(), 0x102: threading.Event()}
    errors = []

    def makeup(instance_id):
        entered.set()
        release[instance_id].wait(5)
        return {"object_definition_size": 1, "structure_size": 4, "member_count": 1, "structure_handle": 1}

    def lookup(name):
        try:
            plc.get_tag_info(name)
        except Exception as err:
            errors.append(err)

    tags = [raw_tag("a"), raw_tag("b")]
    tags[0]["symbol_type"], tags[1]["symbol_type"] = 0x8101, 0x8102
    dtype = {"name": "T", "internal_tags": {}, "attributes": [], "template": {}, "type_class": DINT}
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=tags), \
            mock.patch.object(plc, "_get_structure_makeup", side_effect=makeup), \
            mock.patch.object(plc, "_read_template"), \
            mock.patch.object(plc, "_parse_template_data", return_value=dtype):
        a = threading.Thread(target=lookup, args=("a",))
        a.start(); entered.wait(5)
        b = threading.Thread(target=lookup, args=("b",))
        b.start(); b.join(0.2)  # b's load starts while a is reading its template
        release[0x101].set(); a.join(5)
        release[0x102].set(); b.join(5)
    assert not errors and set(plc.tags) == {"a", "b"}


def test_lazy_reopen_keeps_a_shared_tag_dict():
    eager = driver(definition("a"))
    lazy = LogixDriver("127.0.0.1", lazy_tags=True)
    lazy._tags = eager.tags  # sharing one tag list between connections, as the docs suggest
    with mock.patch.object(CIPDriver, "open", return_value=True), mock.patch.object(lazy, "_initialize_driver"):
        lazy.open()
    assert set(eager.tags) == {"a"} and lazy.tags == {}


def test_metadata_failure_can_be_retried():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=[raw_tag("a")]), \
            mock.patch.object(plc, "_create_tag", side_effect=[RequestError("bad metadata"), definition("a")]):
        with pytest.raises(RequestError):
            plc.get_tag_info("a")
        assert "a" not in plc.tags
        assert plc.get_tag_info("a")["data_type_name"] == "DINT"


def test_open_is_idempotent_after_initialization():
    plc = driver(definition("a"))
    with mock.patch.object(plc, "_initialize_driver") as initialize:
        assert plc.open()
    initialize.assert_not_called()


@pytest.mark.parametrize("error", [RequestError, KeyboardInterrupt])
def test_initialization_failure_closes_socket(error):
    # also on Ctrl-C, else the next open() would return True with no definitions
    plc = LogixDriver("127.0.0.1")
    with mock.patch.object(CIPDriver, "open", return_value=True), \
            mock.patch.object(plc, "_initialize_driver", side_effect=error), \
            mock.patch.object(plc, "close") as close:
        with pytest.raises(error):
            plc.open()
    close.assert_called_once()


def test_actual_write_serialization_does_not_duplicate_payload():
    plc = driver(definition("numbers", DINT, 120))
    transport = mock.Mock()
    transport.receive.return_value = bytes(46) + b"\xcd\x00\x00\x00"
    plc._sock = transport
    result = plc.write("numbers{100}", list(range(100)))
    assert result
    packet = transport.send.call_args[0][0]
    assert len(packet[44:]) <= plc.connection_size
    payload = b"".join(DINT.encode(i) for i in range(100))
    assert packet.endswith(payload)
    assert packet.count(payload) == 1
    assert struct.unpack_from("<H", packet, 2)[0] == len(packet) - 24


def test_scalar_bool_array_write_without_index_updates_first_bit():
    plc = driver(definition("flags", DWORD, 3))
    controller = Controller({"flags[0]": 0})
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        result = plc.write("flags", True)
    assert result and result.type == "BOOL"
    assert controller.values["flags[0]"] == 1


def test_list_written_to_one_bool_is_rejected():
    plc = driver(definition("flags", DWORD, 3))
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.write("flags", [False] * 4)  # a non-empty list would set the bit
    assert result.error and not result
    send.assert_not_called()


def test_lazy_struct_resolution_fetches_only_requested_template():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    used = raw_tag("used")
    used["symbol_type"] = 0x8101
    unused = raw_tag("unused")
    unused["symbol_type"] = 0x8102
    dtype = {
        "name": "Example", "internal_tags": {"member": definition("member")},
        "attributes": ["member"], "type_class": DINT,
        "template": {"structure_size": 4, "structure_handle": 1},
    }
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=[used, unused]), \
            mock.patch.object(plc, "_get_data_type", return_value=dtype) as template:
        assert plc.get_tag_info("used.member")["data_type_name"] == "DINT"
    template.assert_called_once_with(0x101, 0x8101)
    assert set(plc.tags) == {"used"}


def test_bool_word_masks_share_one_multi_service_packet():
    plc = driver(definition("flags", DWORD, 4))
    controller = Controller({f"flags[{i}]": 0 for i in range(4)})
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send) as send:
        result = plc.write("flags[1]{70}", [True] * 70)
    assert result
    assert send.call_count == 1
    packet = controller.sent[0]
    assert isinstance(packet, MultiServiceRequestPacket)
    assert len(packet.requests) == 3
    assert len(packet.build_message()) <= plc.connection_size


@pytest.mark.parametrize("operation", ["read", "write"])
def test_invalid_array_index_returns_a_tag_error(operation):
    plc = driver(definition("numbers", DINT, 100))
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.read("numbers[-1]") if operation == "read" else plc.write("numbers[-1]", 1)
    assert result.error and not result
    send.assert_not_called()


class OrderedController(Controller):
    """Apply whole-word writes as well as masks to check their combined effects."""

    def send(self, request):
        if isinstance(request, WriteTagRequestPacket):
            dtype = request.tag_info["type_class"]
            element = dtype.element_type if hasattr(dtype, "element_type") else dtype
            base, start = get_array_index(request.tag)
            for index in range(request.elements):
                data = request.value[index * element.size:(index + 1) * element.size]
                value = struct.unpack("<I", data)[0] if element == DWORD else element.decode(data)
                name = f"{base}[{(start or 0) + index}]" if hasattr(dtype, "element_type") else base
                self.values[name] = value
        return super().send(request)


@pytest.mark.parametrize("size,micro800", [(50, False), (500, False), (500, True)])
@pytest.mark.parametrize("writes,expected", [
    ([("number.0", True), ("number", 0)], 0),
    ([("number", 1), ("number.0", False)], 0),
    ([("number.0", True), ("number", 2), ("number.1", False)], 0),
    ([("number.0", True), ("other", 9), ("number.1", True)], 3),
])
def test_mixed_bit_and_whole_word_writes_preserve_caller_order(size, micro800, writes, expected):
    plc = driver(definition("number"), definition("other"), connection_size=size, micro800=micro800)
    controller = OrderedController({"number": 0, "other": 0})
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        results = plc.write(*writes)
    assert len(results) == len(writes) and all(results)
    assert controller.values["number"] == expected
    masks = [request for request in controller.sent if isinstance(request, ReadModifyWriteRequestPacket)]
    assert len({request.request_id for request in masks}) == len(masks)


@pytest.mark.parametrize("size,micro800", [(50, False), (500, False), (500, True)])
def test_bool_array_masks_stay_on_correct_side_of_full_word_writes(size, micro800):
    plc = driver(definition("flags", DWORD, 3), connection_size=size, micro800=micro800)
    controller = OrderedController({f"flags[{i}]": 0 for i in range(3)})
    writes = [("flags[31]{2}", [True, True]), ("flags{64}", [False] * 64),
              ("flags[30]{3}", [True, False, True])]
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        results = plc.write(*writes)
        read_result = plc.read("flags{64}")
    assert all(results) and read_result
    assert read_result.value == [False] * 30 + [True, False, True] + [False] * 31
    masks = [request for request in controller.sent if isinstance(request, ReadModifyWriteRequestPacket)]
    assert len({request.request_id for request in masks}) == len(masks)


def test_separate_mask_groups_keep_individual_errors():
    plc = driver(definition("number"))
    controller = OrderedController({"number": 0})
    first_mask = True

    def send(request):
        nonlocal first_mask
        if isinstance(request, ReadModifyWriteRequestPacket) and first_mask:
            first_mask = False
            return reply(request, status=5)
        return controller.send(request)

    # The fake multi-service controller calls itself recursively. Use individual
    # packets so the injected first-mask rejection is also observed at send().
    plc._micro800 = True
    with mock.patch.object(CIPDriver, "send", side_effect=send):
        results = plc.write(("number.0", True), ("number", 2), ("number.1", False))
    assert results[0].error and results[1].error is None and results[2].error is None
    assert controller.values["number"] == 0


def test_lazy_definition_comm_error_is_not_a_tag_error():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    with mock.patch.object(plc, "_get_instance_attribute_list_service", side_effect=CommError("lost")):
        with pytest.raises(CommError):
            plc.read("a")


def test_lazy_lookup_is_case_insensitive():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=[raw_tag("MyTag")]):
        assert plc.get_tag_info("mytag")["tag_name"] == "MyTag"
        assert plc.get_tag_info("MYTAG") is plc.tags["MyTag"]
    assert set(plc.tags) == {"MyTag"}


def test_failed_partial_read_fallback_is_a_tag_error():
    plc = driver(definition("a"), definition("b"))
    controller = Controller(fail={"a": 6})

    def send(request):
        if isinstance(request, ReadTagFragmentedRequestPacket):
            raise RequestError("fallback failed")
        return controller.send(request)

    with mock.patch.object(CIPDriver, "send", side_effect=send):
        results = plc.read("a", "b")
    assert results[0].error == "fallback failed" and results[1].value == 12


def test_bool_slice_rejects_string_values_and_sends_nothing():
    plc = driver(definition("flags", DWORD, 3))
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.write("flags[30]{3}", [True, "False", True])
    assert not result and "Invalid value for BOOL" in result.error
    send.assert_not_called()
