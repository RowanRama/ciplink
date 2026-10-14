=============
CIP Reference
=============

Documented CIP service and class codes are available in enum-like classes that can be imported for use, mostly useful for
generic messaging.  The following classes may be imported directly from the ``ciplink`` package.

Ethernet/IP Encapsulation Commands
==================================

.. literalinclude:: ../ciplink/cip/services.py
    :pyobject: EncapsulationCommands


CIP Services and Class Codes
=============================

.. literalinclude:: ../ciplink/cip/services.py
    :pyobject: Services

.. literalinclude:: ../ciplink/cip/object_library.py
    :pyobject: ClassCode

.. literalinclude:: ../ciplink/cip/object_library.py
    :pyobject: CommonClassAttributes


Identity Object
===============

.. literalinclude:: ../ciplink/cip/object_library.py
    :pyobject: IdentityObjectInstanceAttributes


Connection Manager Object
=========================

.. literalinclude:: ../ciplink/cip/services.py
    :pyobject: ConnectionManagerServices

.. literalinclude:: ../ciplink/cip/object_library.py
    :pyobject: ConnectionManagerInstances


File Object
===========

.. literalinclude:: ../ciplink/cip/services.py
    :pyobject: FileObjectServices

.. literalinclude:: ../ciplink/cip/object_library.py
    :pyobject: FileObjectClassAttributes

.. literalinclude:: ../ciplink/cip/object_library.py
    :pyobject: FileObjectInstanceAttributes

.. literalinclude:: ../ciplink/cip/object_library.py
    :pyobject: FileObjectInstances