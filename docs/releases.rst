===============
Release History
===============

Unreleased
==========

- |:sparkles:| ``ciplink-server``: the tag server on the Rust core, a port of the Python ciplink-tagserver 0.4 with
  the same config files, WebSocket protocol and HTTP API (``@ciplink/react`` apps work unchanged).  It comes with
  every binding: the ``ciplink-server`` command and ``ciplink.server.TagServer`` in the Python package, the
  ``ciplink-server`` crate, ``ciplink_server_start`` in C, ``ciplink::Server`` in C++ and ``Ciplink.TagServer`` in C#,
  and an executable per platform on the GitHub release.  See ``docs/server.md``.
- |:bug:| scalar bit strings are no longer taken for BOOL arrays: a ``DWORD`` read by name gives its 32 bits (not bit
  0), ``Name.n`` reads bit n of a ``BYTE``, ``WORD``, ``DWORD`` or ``LWORD`` (a tag, member or array element) and
  writes it with a Read-Modify-Write of ``Name`` itself.  Only a ``DWORD`` with dimensions is a BOOL array.
  ``ciplink-sim`` has ``BYTE``, ``WORD`` and ``LWORD`` tags and members.

ciplink 0.3.3
=============

- |:sparkles:| device browsing like RSWho: ``get_ports()``, ``browse_port()``, ``iter_port()`` and ``get_identity()``
  list a device's ports, the modules, nodes or (on an EtherNet/IP port) the devices of its subnet, and the identity at
  any route through them, probing from several connections at once.  Every binding has it: Python and Rust, C++
  (``get_ports``, ``browse_port``, ``scan_port``), C# (``GetPorts``, ``BrowsePort``, ``ScanPort``) and C
  (``ciplink_get_ports``, ``ciplink_browse_port``, ``ciplink_scan_port``).  ``examples/device_browser.py`` is a tree
  browser built on them.
- |:bug:| ``discover()`` broadcasts on every network adapter that is up, not only on the addresses the host name
  resolves to (which can leave out a plant network adapter with a static address), and on all of them at once.
- |:sparkles:| ``ciplink-sim`` answers the Port Object and TCP/IP Interface Object (a backplane and an EtherNet/IP
  port); ``chassis_size`` sets the slots of its backplane, ``ip``/``netmask`` its port and ``network`` the devices
  on its network.

ciplink 0.3.2
=============

- |:sparkles:| controller-side trends: the controller samples tags at a fixed period (down to 1 ms) into the trend
  object Studio 5000 uses, and the driver uploads the samples in batches on a connection of its own, each with the
  controller's timestamp.  A pen is any atomic tag, member or array element of up to 32 bits (BOOL, SINT, INT, DINT,
  USINT, UINT, UDINT, REAL) or a bit; 64-bit types cannot be trended.  ``LogixDriver.trend()`` in Python, Rust and
  C++, ``LogixDriver.Trend()`` in C#, ``ciplink_trend_start`` in C.
- |:sparkles:| ``ciplink-sim`` simulates the trend object.

ciplink 0.3.1
=============

- |:memo:| the NuGet package now has a README and links to the project and its repository.

ciplink 0.3.0
=============

- |:sparkles:| the driver core is written in Rust (``crates/ciplink``) and the Python package drives it through the
  extension module ``ciplink._core``.  The Python API, the requests sent (byte for byte), the results and the error
  messages are those of 0.2.0; reads and writes take a third to a quarter of the client CPU, and opening a connection
  with a large tag list (or from the tag cache file) is four to six times faster.  The GIL is released during network
  I/O.
- |:sparkles:| the same core is available from C (``ciplink.h``), C++ (header-only ``ciplink.hpp``), C# (.NET 8+)
  and Rust, see ``bindings/README.md``.
- |:sparkles:| ``ciplink-sim``, a simulated Logix, Micro800 or SLC 500 controller for tests in any language.
- |:boom:| **[Breaking]** the wheels are platform specific (abi3, one per platform for Python 3.9+), and installing
  from source needs a Rust toolchain.  Driver internals the Python driver had (``_sock``, ``send``, ``_forward_open``,
  ``_read_tag``, ``encode_value``...) are gone; code that patched them must use the public API.

ciplink 0.2.0
=============

LogixDriver
-----------

- |:sparkles:| every ``read``, ``write``, ``get_tag_description`` and ``authenticate_metadata`` error is a ``TagError``,
  a ``str`` with a ``kind`` (``ErrorKind``) and the CIP ``status`` and first extended status word ``ext`` of a
  controller error.  ``Tag.error_kind`` is the kind, ``None`` without an error and ``OTHER`` for a plain string.
  Kinds: ``NOT_FOUND`` (no such tag, member, element or bit), ``BAD_VALUE`` (the write value does not fit the type),
  ``BAD_REQUEST`` (malformed request), ``ACCESS`` (privilege, AOI local tag, keyswitch or password), ``REFUSED``
  (nothing done, retry later: reload backoff, state conflict, upload/download mode), ``TABLE_CHANGED`` (the tag table
  changed during the request), ``COMM`` (request or reply lost or unparseable), ``DEVICE`` (any other controller
  status) and ``OTHER``.  The error messages are unchanged.
- |:boom:| **[Breaking]** write values are checked strictly, a value that does not fit is rejected for that tag
  (``BAD_VALUE``, nothing is sent for it, the other tags are still written):

  - an array given more values than elements (it was truncated)
  - BOOL values other than ``True``/``False`` or the ints ``0``/``1`` (any truthy value set the bit), also for
    BOOL arrays, bit members of structures and bits of integers
  - ``True``/``False`` for an integer, ``REAL`` or ``LREAL``
  - a structure dict with keys that are not members (they were ignored)

  The BOOL and number checks are in the data types, so ``SLCDriver`` word writes reject ``True``/``False`` too
  (``write('N7:0', True)``, write ``1``), bit writes like ``B3:0/1`` still take any value.
- |:sparkles:| ``get_tag_descriptions(*tag_names)`` reads many Descriptions at once, a list of the same results as
  ``get_tag_description`` of each tag, sending one round of multi-service packets per candidate path (element,
  member, base) instead of one request per tag and path.  ``get_tag_description`` uses it.

1.3.0 (unreleased)
==================

- |:boom:| **[Breaking]** a request that fails with a ``CommError`` (timeout, connection reset) now closes the
  connection, call ``open()`` again to reconnect.  A ``with`` block raises ``CommError`` if the connection cannot be opened.
- |:sparkles:| requests on one driver are sent one at a time, so a driver can be shared between threads
- |:bug:| fixed ``STRING2``, empty ``STRINGN``, ``DATE_AND_TIME`` inside structs and signed ``TIME32``;
  data shorter than the type now raises ``DataError``
- |:bug:| ``configure_default_logger`` replaces the handlers of a previous call instead of adding more

CIPDriver
---------

- |:boom:| **[Breaking]** ``generic_message`` only uses ``route_path`` with ``unconnected_send=True``,
  any other path must be part of ``request_data``
- |:bug:| ``generic_message`` replies without data (e.g. ``Set_Attribute_Single``) no longer fail when ``data_type``
  is set, the value is ``b''``
- |:bug:| ``list_identity`` no longer uploads the tag list when called on ``LogixDriver`` and always closes its connection
- |:sparkles:| added ``socket_timeout`` and ``connection_size`` keyword arguments

LogixDriver
-----------

- |:sparkles:| added ``lazy_tags=True`` to load tag definitions on demand instead of uploading them on connect
- |:sparkles:| BOOL array slices that do not start or end on a 32-bit boundary can be read and written
- |:sparkles:| one-dimensional arrays with more than 65,535 elements are split into several requests
- |:sparkles:| tag names are case-insensitive (an exact match is tried first)
- |:bug:| ``write()`` keeps the call order, pending bit masks are sent before a following whole-value write
- |:bug:| multi-service packets are sized by their exact request and reply bytes, a partial reply is read again
  as a fragmented read
- |:bug:| array indexes and instance ids above 65535 (32-bit) are encoded correctly
- |:bug:| writing a string or ``None`` to a BOOL or a bit returns an error instead of writing ``True``
- |:bug:| a failed ``open()`` closes the connection, connection errors during init and tag upload are raised as ``CommError``

SLCDriver
---------

- |:bug:| fixed ``B3/n`` bit addresses and writes to timer/counter ``.PRE``/``.ACC``
- |:bug:| ``ST`` string writes send the full 84-byte element
- |:bug:| invalid addresses like ``N7:1000`` are rejected instead of being read as another address
- |:sparkles:| uses the standard Forward Open directly

1.2.16
======

- |:sparkles:| added ``DT``, ``LDT`` and ``TIME32`` data types #332

LogixDriver
-----------

- |:bug:| ``get_plc_time`` reads the UTC system time (attribute 6) and returns a timezone-aware ``datetime``,
  in local time unless ``tz`` is given #276 #306
- |:sparkles:| added ``tag_namespace_filter`` to only upload tags whose name starts with a prefix #312

SLCDriver
---------

- |:bug:| fixed odd-length string writes and garbage data on string reads #331

1.2.14
======

- |:sparkles:| add support for hostnames in connection path

1.2.13
======

CIPDriver
---------
- |:sparkles:| add ability to specify broadcast address for `discover()` #292 @tlf30

1.2.11
======

- |:sparkles:| update vendor id list #257 @PhilippHaefele

1.2.10
======

CIPDriver
---------
- |:sparkles:| support port customization in the connection path
- |:sparkles:| support comma delimiters in the connection path

1.2.9
=====

SLCDriver
---------
- |:sparkles:| added `get_datalog_queue` method @ddeckerCPF

1.2.8
=====

LogixDriver
-----------

- |:bug:| fixed issue reading single elements >32 from BOOL arrays

1.2.7
=====

LogixDriver
-----------

- |:bug:| fixed issue with program-scoped tags in `get_tag_info` #216

1.2.6
=====

LogixDriver
-----------

- |:bug:| fixed issue handling BOOLs in some predefined types #197

1.2.5
=====

LogixDriver
-----------

- |:bug:| fixed issue parsing struct definitions for predefined types for v32+ #186

1.2.4
=====

LogixDriver
-----------

- |:bug:| fixed issue for BOOL members inside structures that was introduced as part of 1.2.3 #182

1.2.3
=====

LogixDriver
-----------

- |:bug:| fixed issue with bit-level access to integers inside nested structs #170

1.2.2
=====

CIPDriver
---------

- |:sparkles:| added support for string CIP paths in `generic_message` for `route_path`
- |:bug:| fixed bug where errors during discovery prevent any results from being returned
- |:bug:| fixed issue where ``get_module_info`` would always use first hop in path instead of the last

LogixDriver
-----------

- |:bug:| fixed issue with multi-request message size tracking being off by 2 bytes
- |:bug:| fixed issue with AOI structure handling with > 8 BOOL members being mapped to types larger than a USINT (SISAutomationIMA)

1.2.1
=====

- |:sparkles:| added ability to configure custom logger via the `configure_default_logger` function


1.2.0
=====

- |:bug:| fixed issue with logging configuration
- |:art:| formatted project with black
- |:memo:| misc. documentation updates

LogixDriver
-----------

- |:bug:| fixed issue with writing a tag multiple times failing after the first write
- |:sparkles:| added `tags_json` property

SLCDriver
---------

- |:bug:| fixed issue with parsing IO addresses
- |:zap:| improved address parsing speed by pre-compiling regex



1.1.1
=====

LogixDriver
-----------

- |:bug:| fixed read/write errors by preventing program-scoped tags from using instance ids in the request


1.1.0
=====

LogixDriver
-----------

- |:bug:| fixed bugs in handling of built-in types (TIMER, CONTROL, etc)
- |:bug:| fixed bugs in structure tag handling when padding exists between attributes
- |:sparkles:| changed the meaning of the element count for BOOL arrays
    - Previously, the ``{#}`` referred to the underlying ``DWORD`` elements of the ``BOOL`` array.
      A ``BOOL[64]`` array is actually a `DWORD[2]` array, so ``array{1}`` translated to BOOL elements
      0-31 or the first ``DWORD`` element. Now, the ``{#}`` refers to the number of ``BOOL`` elements.  So
      ``array{1}`` is only a single ``BOOL`` element and ``array{32}`` would be the 0-31 ``BOOL`` elements.
    - Refer to the documentation_ for limitations on writing.

.. _documentation: https://docs.pycomm3.dev/en/latest/usage/logixdriver.html#bool-arrays

1.0.1
=====

- |:bug:| Fixed incorrect/no error in response Tag for some failed requests in a multi-request
- |:recycle:| Minor refactor to status and extended status parsing



1.0.0
=====

- |:sparkles:| New type system to replace the ``Pack`` and ``Unpack`` helper classes
    - New types represent any CIP type or object and allow encoding and decoding of values
    - Allows users to create their own custom types
    - |:boom:| **[Breaking]** ``generic_message`` replaced the ``data_format`` argument with ``data_type``, see documentation for details.
- |:sparkles:| Added a new ``discover()`` method for finding Ethernet/IP devices on the local network
- |:sparkles:| Added a ``configure_default_logger`` method for simple logging setup
    - Packet contents are now logged using a custom ``VERBOSE`` level
- |:art:| Internal package structure changed.
- |:recycle:| Lots of refactoring, decoupling, etc
- |:white_check_mark:| Increased test coverage
- |:memo:| New and improved documentation
    - |:construction:| Still a work-in-progress


Logix Driver
------------

- |:triangular_flag_on_post:| Upload of program-scoped tags is now enabled by default
    - Use ``init_program_tags=False`` in initializer for to upload controller-scoped only tags
- |:boom:| Removed the ``init_info`` and ``micro800`` init args and the ``use_instance_ids`` property
    - These have all been automatic for awhile now, but were left for backwards compatibility
    - If you need to customize this behavior, override the ``_initialize_driver`` method
