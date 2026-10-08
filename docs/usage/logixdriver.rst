.. py:currentmodule:: pycomm3

=================
Using LogixDriver
=================


Tags and Data Types
===================

When creating the driver it will automatically upload all of the controller scope tag and their data type definitions.
These definitions are required for the :meth:`~LogixDriver.read` and :meth:`~LogixDriver.write` methods to function.
Those methods abstract away a lot of the details required for actually implementing the Ethernet/IP protocol. Uploading
the tags could take a few seconds depending on the size of program and the network.  It was decided this small
upfront overhead provided a greater benefit to the user since they would not have to worry about specific implementation
details for different types of tags.  The ``init_tags`` kwarg is ``True`` by default, meaning that all of the controller
scoped tags will be uploaded. ``init_program_tags`` is a separate flag to control whether or not all the program-scoped
tags are uploaded as well.  By default, ``init_program_tags`` is ``True``, set to ``False`` to disable and only upload
controller-scoped tags.

Below shows how the init tag options are equivalent to calling the :meth:`~LogixDriver.get_tag_list` method.
:meth:`~LogixDriver.get_tag_list` replaces :attr:`~LogixDriver.tags` unless ``cache=False``.  Each upload creates new
``type_class`` objects, so compare uploads with :attr:`~LogixDriver.tags_json`, which leaves them out.

>>> plc1 = LogixDriver('10.20.30.100')
>>> plc1.open()  # uploads controller and program tags
>>> plc2 = LogixDriver('10.20.30.100', init_tags=False)
>>> plc2.open()
>>> plc2.get_tag_list(program='*')  # '*' = controller and all program tags
>>> plc1.tags_json == plc2.tags_json
True
>>> plc3 = LogixDriver('10.20.30.100', init_program_tags=False)
>>> plc3.open()  # uploads controller-scoped tags only
>>> plc4 = LogixDriver('10.20.30.100', init_tags=False)
>>> plc4.open()
>>> plc4.get_tag_list()  # controller-scoped only
>>> plc3.tags_json == plc4.tags_json
True


Loading Definitions on Demand
-----------------------------

For applications that access only a few tags, use ``lazy_tags=True``::

    with LogixDriver('10.20.30.100', lazy_tags=True) as plc:
        result = plc.read('Motor.Speed')
        print(result.value, result.error)

This option overrides ``init_tags`` and skips the tag upload during connection
initialization. The first request in a controller or program scope uploads that
scope's symbol list. Only the requested tags and their required structure
templates are resolved. Later requests reuse those definitions. Program scopes
are loaded independently, without uploading unrelated programs.

The ``tags`` property contains only the definitions resolved so far. Use
``get_tag_list(program='*')`` when a complete inventory is needed. Reopening a
lazy driver clears its definitions so they are refreshed for the new session.
``init_tags=False`` without lazy mode continues to require a supplied tag cache
or an explicit call to ``get_tag_list``.


Tag Structure
-------------

Each tag definition is a dict containing all the details retrieved from the PLC.  :meth:`~LogixDriver.get_tag_list`
returns a list of dicts for the tag list while the :attr:`LogixDriver.tags` property stores them as a dict of ``{tag name: definition}``.

**Tag Definition Properties:**

tag_name
    Symbolic name of the tag

instance_id
    Internal PLC identifier for the tag.  Used for reads/writes on v21+ controllers. Saves space in packet by not requiring
    the full tag name to be encoded into the request.

tag_type
    - ``'atomic'`` base data types like BOOL, DINT, REAL, etc.
    - ``'struct'`` complex data types like STRING, TIMER, PID, etc as well as UDTs and AOIs.

.. _data_type:

data_type
    - ``'DINT'``/``'REAL'``/etc name of data type for atomic types
    - ``{data type definition}`` for structures, detailed in `Structure Definitions`_

data_type_name
    - the string name of the data type: ``'DINT'``/``'REAL'``/``'TIMER'``/``'MyCoolUDT'``

string
    **Optional** string size if the tag is a STRING type (or custom string)

external_access
    ``'Read/Write'``/``'Read Only'``/``'None'`` matches the External Access tag property in the PLC

dim
    number dimensions defined for the tag

    - ``0`` - not an array
    - ``1-3`` - a 1 to 3 dimension array tag, e.g. ``DINT[5] -> 1, DINT[5,5] -> 2, DINT[5,5,5] -> 3``

dimensions
    length of each dimension defined, ``0`` if dimension does not exist.  ``[dim0, dim1, dim2]``

    - ``DINT[5] -> [5, 0, 0]``
    - ``DINT[5, 10] -> [5, 10, 0]``
    - ``DINT[5, 10, 15] -> [5, 10, 15]``

alias
    ``True``/``False`` if the tag is an alias to another.

    .. note:: This is not documented, but an educated guess found through trial and error.

type_class
    the :class:`~pycomm3.cip.data_types.DataType` that was created for this tag


Structure Definitions
---------------------

While uploading the tag list, any tags with complex data types will have the full definition of structure uploaded as well.
Inside a tag definition, the `data_type`_ attribute will be a dict containing the structure definition.  The :attr:`LogixDriver.data_types`
property also provides access to these definitions as a dict of ``{data type name: definition}``.

**Data Type Properties:**

name
    Name of the data type, UDT, AOI, or builtin structure data types

attributes
    List of names for each attribute in the structure. Does not include internal tags not shown in Logix, like the host
    DINT tag that BOOL attributes are mapped to.

template
    ``dict`` with template definition. Used internally within LogixDriver, allows reading/writing of full structs and
    allows the read/write methods to monitor the request/response size.

internal_tags
    A ``dict`` with each attribute (including internal, not shown in Logix attributes) of the structure containing the
    definition for the attribute, ``{attribute: {definition}}``.

    **Definition:**

    tag_type
        Same as `Tag Structure`_

    data_type
        Same as `Tag Structure`_

    data_type_name
        Same as `Tag Structure`_

    string
        Same as `Tag Structure`_

    offset
        Location/Byte offset of this tag's data in the response data.

    bit
        **Optional** BOOL tags are aliased to internal hidden integer tags, this indicates which bit it is aliased to.

    array
        **Optional** Length of the array if this tag is an array, ``0`` if not an array,

.. note:: ``attributes`` and ``internal_tags`` do **NOT** include InOut parameters.

type_class
    The :class:`~pycomm3.cip.data_types.DataType` type that was created to represent this structure


Reading/Writing Tags
====================

All reading and writing is handled by the :meth:`~LogixDriver.read` and :meth:`~LogixDriver.write` methods.  The original
pycomm and other similar libraries will have different methods for handling different types like strings and arrays, this
is not necessary in ``pycomm3`` due to uploading the tag list and creation of a :class:`~pycomm3.cip.data_types.DataType`
class for each type. Both methods accept any number of tags, they will automatically use the *Multiple Service Packet (0x0A)*
service and track the request/return data size making sure to stay below the connection size.  If there is a tag value
that cannot fit within the request/reply packet, it will automatically handle that tag independently using the
*Read Tag Fragmented (0x52)* or *Write Tag Fragmented (0x53)* requests.  Users do not have to worry about the number of
tags or their size in any single request, this is all handled automatically by the driver.

Program-Scoped Tags
-------------------

Program-scoped tag names use the format `Program:<program>.<tag>`.  For example, to access a tag named `SomeTag` in
the program `MainProgram` you would use `Program:MainProgram.SomeTag` in the request.  The tag list uploaded by the
driver will also keep this format for the tag names.


Array Tags
----------

To access an index of an array, include the index inside square brackets after the tag name.  The format is the same as
in Logix, where multiple dimensions are comma separated, e.g. ``an_array[5]`` for the 5th element of ``an_array`` or
``array2[1,0]`` to access the first element of the second dimension of ``array2``.  Not specifying an index is equivalent
to index 0, i.e ``array == array[0]``.

Whether reading or writing, the number of elements needs to be specified.  To do so, specify the number
of elements inside curly braces at the end of the tag name, e.g. ``an_array{5}`` for 5-elements of ``an_array``.
If omitted, the number of elements is assumed to be 1, i.e. ``an_array == an_array[0] == an_array[0]{1}``. Only a single
element count is used. For 2 and 3 dimensional arrays, the element count is the total number of elements across all
dimensions.  The tables below show a couple examples of how the element count works for multi-dimension arrays.


======================   ========  =============
array (``DINT[3, 2]``)   array{4}  array[1,1]{3}
======================   ========  =============
array[0, 0]                X
array[0, 1]                X
array[1, 0]                X
array[1, 1]                X        X
array[2, 0]                         X
array[2, 1]                         X
======================   ========  =============

=========================    ========    ===============
array (``SINT[2, 2, 2]``)    array{4}    array[0,1,0]{5}
=========================    ========    ===============
array[0, 0, 0]               X
array[0, 0, 1]               X
array[0, 1, 0]               X           X
array[0, 1, 1]               X           X
array[1, 0, 0]                           X
array[1, 0, 1]                           X
array[1, 1, 0]                           X
array[1, 1, 1]
=========================    ========    ===============

BOOL Arrays
^^^^^^^^^^^

BOOL arrays work a little differently due them being implemented as DWORD arrays in the PLC. (That is the reason you can
only make BOOL arrays in multiples of 32, DWORDs are 32 bits.) The element count in the request (``'{#}'``)
represents the number of BOOL elements. Reads start at the first DWORD containing
the requested slice. Writes may start at any BOOL index and span word boundaries::

    plc.write('bools[30]{5}', [True, False, True, True, False])

Partial words use Read-Modify-Write masks to preserve all unrequested bits. Aligned
slices containing complete DWORDs use ordinary tag writes. Each word update is
independent; a slice spanning multiple words is not a single atomic operation.
A failed word update is reported in the returned Tag even if other words succeed.

Reading Tags
------------

:meth:`LogixDriver.read` accepts any number of tags, all that is required is the tag names. Reading of entire structures
is supported as long as none of the attributes have an external access of *None*.
To read a structure, just request the base name and the ``value`` for the ``Tag`` object will be a dict of ``{attribute: value}``

Read an atomic tag

>>> plc.read('dint_tag')
Tag(tag='dint_tag', value=0, type='DINT', error=None)

Read multiple tags

>>> plc.read('tag_1', 'tag_2', 'tag_3')
[Tag(tag='tag_1', value=100, type='INT', error=None), Tag(tag='tag_2', value=True, type='BOOL', error=None), ...]

Read a structure

>>> plc.read('simple_udt')
Tag(tag='simple_udt', value={'attr1': 0, 'attr2': False, 'attr3': 1.234}, type='SimpleUDT', error=None)

Read arrays

>>> plc.read('dint_array{5}')  # starts at index 0
Tag(tag='dint_array', value=[1, 2, 3, 4, 5], type='DINT[5]', error=None)
>>> plc.read('dint_array[20]{3}') # read 3 elements starting at index 20
Tag(tag='dint_array[20]', value=[20, 21, 22], type='DINT[3]', error=None)

One-dimensional non-BOOL arrays with more than 65,535 requested elements are
split into consecutive service requests and returned as one Tag. Both reads and
writes support a nonzero starting index. Packet fragmentation handles the bytes
within each service request. Larger service counts for BOOL arrays and
multidimensional arrays return a request error. Transfers spanning several
requests do not provide a simultaneous snapshot or an atomic write.

Verify all reads were successful

>>> tag_list = ['tag1', 'tag2', ...]
>>> results = plc.read(*tag_list)
>>> if all(results):
...     print('All tags read successfully')
All tags read successfully


Writing Tags
------------

:meth:`LogixDriver.write` method accepts any number of tag-value pairs of the tag name and value to be written.
For writing a single tag, you can do ``write(<tag name>, <value>)``, but for multiple tags a sequence of tag-value tuples
is required (``write((<tag1>, <value1>), (<tag2>, <value2>))``). For arrays, the value should be a list of the values to write.
If the value list is shorter than the requested element count, that tag is not written and its returned Tag has its error
set (the Tag is falsy); extra values in a list that is too long are ignored.  Writing a
structure is supported as long as all attributes have Read/Write external access.  The value for a struct should be a
``dict`` of ``{<attribute name>: <value>}``, nesting as needed.  It is not recommended to write full structures for builtin types,
like ``TIMER``, ``PID``, etc.

Bit writes to the same word can share a Read-Modify-Write request. Pending bit
masks are sent before a following whole-tag or array write, so overlapping bit
and whole-value writes follow the supplied order.

Write a tag

>>> plc.write('dint_tag', 100)
Tag(tag='dint_tag', value=100, type='DINT', error=None)

Write many tags

>>> plc.write(('tag_1', 1), ('tag_2', True), ('tag_3', 1.234))
[Tag(tag='tag_1', value=1, type='INT', error=None), Tag(tag='tag_2', value=True, type='BOOL', error=None), ...]

Write arrays

>>> plc.write('dint_array{10}', list(range(10)))  # starts at index 0
Tag(tag='dint_array', value=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], type='DINT[10]', error=None)
>>> plc.write(('dint_array[10]{3}', [10, 11, 12]))  # write 3 elements starting at index 10
Tag(tag='dint_array[10]', value=[10, 11, 12], type='DINT[3]', error=None)

Write structures

>>> plc.write('my_udt', {'attr1': 100, 'attr2': [1, 2, 3, 4]})
Tag(tag='my_udt', value={'attr1': 100, 'attr2': [1, 2, 3, 4]}, type='MyUDT', error=None)

Check if all writes were successful

>>> tag_values = [('tag1', 10), ('tag2', True), ('tag3', 12.34)]
>>> results = plc.write(*tag_values)
>>> if all(results):
...     print('All tags written successfully')
All tags written successfully


String Tags
-----------

Strings are technically structures within the PLC, but are treated as atomic types in this library.  There is no need
to handle the ``LEN`` and ``DATA`` attributes, the structure is converted to/from Python ``str`` objects transparently.
Any structures that contain only a DINT-``LEN`` and a SINT[]-``DATA`` attributes will be automatically treated as string tags.
This allows the builtin STRING types plus custom strings to be handled automatically.  Writing a string that is longer
than the plc tag returns an error (the tag is not written).

>>> plc.read('string_tag')
Tag(tag='string_tag', value='Hello World!', type='STRING', error=None)
>>> plc.write(('short_string_tag', 'Test Write'))
Tag(tag='short_string_tag', value='Test Write', type='STRING20', error=None)


Repeated Reads
--------------

Keep the connection open around the polling loop, and request all needed tags in
one read call so they can be grouped into packets. Check each returned Tag for
errors. For parallel requests use one driver instance per thread. Repeated calls to open on an already
open driver reuse the connection and its initialized definitions.

The polling example uses a monotonic clock and a configurable interval::

    python -m examples.polling 10.20.30.100 Motor.Speed Motor.Running --interval 1 --lazy-tags

.. literalinclude:: ../../examples/polling.py
    :language: python
