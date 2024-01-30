"""
The SyncServer Client module provides interfaces for interacting with the SyncServer.

This module includes two main classes:
- FileInterface: Provides methods for file-related operations on the SyncServer.
- DirInterface: Provides methods for directory-related operations on the SyncServer.

Usage:
1. Create instances of FileInterface or DirInterface by providing the necessary authentication details.
2. Use the provided methods to perform operations such as file uploads, removals, reading, directory creation,
   deletion, and listing.

Note:
- The SyncServer Client uses the requests library for making HTTP requests to the SyncServer.
- Ensure that the SyncServer is running and accessible from the specified server URL.

Version: 1.0.0
"""

from .interface import FileInterface, DirInterface
__all__ = ['FileInterface', 'DirInterface']
__version__ = "1.0.0"
