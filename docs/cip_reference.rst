=============
CIP Reference
=============

Documented CIP service and class codes are available in enum-like classes that can be imported for use, mostly useful for
generic messaging.  The following classes may be imported directly from the ``ciplink`` package.

Ethernet/IP Encapsulation Commands
==================================

.. literalinclude:: ../python/ciplink/cip/services.py
    :pyobject: EncapsulationCommands


CIP Services and Class Codes
=============================

.. literalinclude:: ../python/ciplink/cip/services.py
    :pyobject: Services

.. literalinclude:: ../python/ciplink/cip/object_library.py
    :pyobject: ClassCode

.. literalinclude:: ../python/ciplink/cip/object_library.py
    :pyobject: CommonClassAttributes


Identity Object
===============

.. literalinclude:: ../python/ciplink/cip/object_library.py
    :pyobject: IdentityObjectInstanceAttributes


Connection Manager Object
=========================

.. literalinclude:: ../python/ciplink/cip/services.py
    :pyobject: ConnectionManagerServices

.. literalinclude:: ../python/ciplink/cip/object_library.py
    :pyobject: ConnectionManagerInstances


File Object
===========

.. literalinclude:: ../python/ciplink/cip/services.py
    :pyobject: FileObjectServices

.. literalinclude:: ../python/ciplink/cip/object_library.py
    :pyobject: FileObjectClassAttributes

.. literalinclude:: ../python/ciplink/cip/object_library.py
    :pyobject: FileObjectInstanceAttributes

.. literalinclude:: ../python/ciplink/cip/object_library.py
    :pyobject: FileObjectInstances