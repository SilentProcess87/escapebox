# Archive Folder Contents

This archive contains the old multi-component implementation of the C2 server system. These files have been replaced by the unified single-executable solution.

## Folder Structure

### `/python_servers/`
Contains the Python-based server components that previously handled:
- WebSocket server functionality
- Web server functionality
- Real-time data analytics
- File operations

### `/batch_scripts/`
Contains batch files used to start various components of the old multi-file system:
- Server startup scripts
- Client startup scripts
- Dashboard launchers

### `/old_cpp_implementations/`
Contains previous C++ implementations:
- Separate client executables
- Individual server components
- Various test implementations
- Old Visual Studio project files

### `/html_dashboards/`
Contains standalone HTML dashboard files that were served by Python servers.
Now replaced by embedded HTML in the unified executable.

### `/old_documentation/`
Contains documentation specific to the old multi-file architecture.

## Why These Were Archived

The original system required:
- Multiple Python scripts running simultaneously
- Batch files to coordinate startup
- Separate executables for different components
- External web server processes

The new unified solution provides all functionality in a single executable with:
- No Python dependencies
- No external scripts needed
- Embedded web dashboard
- Native WebSocket implementation
- Single process architecture

## Note
These files are kept for reference but are no longer needed for the current unified C2 server implementation.

