XWinTab: Tablet Input for Painting on Wine
==========================================

Wine's built-in implementation of Wintab does not work with Rebelle or Expresii. 
XWinTab works around this by being loaded by the application and creating its own connection to X11.

This software is experimental and has not been tested extensively.

Requirements
------------

- A Wacom-compatible tablet that works in native Linux applications. The device name should include "stylus".
- Libraries: ``libxcb.so.1`` and ``libxcb-xinput.so.0``. On Debian/Ubuntu, install the ``libxcb-xinput0`` package.
- To build from source: install ``libxcb-xinput-dev``, ``wine64-tools``, and ``gcc-mingw-w64``.

Installation for Rebelle
------------------------

1. With Rebelle installed, copy **both** ``wintab32.dll`` and ``XWinTabHelper.dll.so`` into the installation directory (the one containing ``Rebelle 7.exe``).
2. Add a DLL override for ``wintab32.dll`` so it loads instead of the built-in version.
3. Configure Rebelle to use the ``Wacom Compatible (wintab)`` input option.

Installation for Expresii
-------------------------

1. With Expresii installed, copy **both** ``wintab32.dll`` and ``XWinTabHelper.dll.so`` into the installation directory (the one containing ``X.exe``).
2. Add a DLL override for ``wintab32.dll`` so it loads instead of the built-in version.
3. Configure Expresii to use the ``Wacom Compatible (wintab)`` input option.

Debugging the DLL
-----------------

1. Run the application with logging enabled, for example::

   env XWINTAB_LOG=1 WINEPREFIX="your_wine_prefix" wine "C:\\\\users\\\\Public\\\\Desktop\\\\application.lnk"

2. An ``XWinTabLog.txt`` file will appear in ``WINEPREFIX/drive_c/users/your_username/`` containing the log.

Implemented API Functions
-------------------------

- Context: ``WTOpenA``, ``WTOpenW``, ``WTClose``, ``WTEnable``, ``WTOverlap``
- Packet: ``WTPacket``, ``WTPacketsGet``, ``WTPacketsPeek``, ``WTQueueSizeGet``, ``WTQueueSizeSet``
- Info: ``WTInfoA``, ``WTInfoW``
- Get/Set: ``WTGetA``, ``WTSetA`` (partial implementations)
- Utilities: ``err_dlg``

For more information about partial implementations, see ``WinTab.c``.

Additional Notes
----------------

This software is provided without any warranty (see ``LICENSE``) and is used at your own risk.

---

*This fork is based on Graham’s original XWinTab implementation with minor improvements and updates.*