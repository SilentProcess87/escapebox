# Port Configuration Fix

## Issue
The web server was configured to listen on port 8080, but the console messages and logs were showing port 9999.

## Fix Applied
Updated the following references in `escapebox.cpp`:

1. **Console output on server startup**:
   - Changed: `http://localhost:9999/` → `http://localhost:8080/`
   - Changed: `http://localhost:9999/api/status` → `http://localhost:8080/api/status`  
   - Changed: `http://localhost:9999/api/command` → `http://localhost:8080/api/command`

2. **Log message**:
   - Changed: `"Web interface active at http://localhost:9999/"` → `"Web interface active at http://localhost:8080/"`

## Technical Details
- The actual web server binding remains on port 8080 (no code change needed)
- The web dashboard HTML uses relative URLs (`/api/*`), so it works on any port
- All console messages now correctly reflect the actual port being used

## Result
The server and all its messages now consistently use port 8080. When you start the server, you'll see:
- Web dashboard: http://localhost:8080/
- API endpoints: http://localhost:8080/api/*

## Testing
1. Rebuild the project: `.\build_release.bat`
2. Start the server: `escapebox.exe server`
3. Open browser to: http://localhost:8080/
4. Verify the dashboard loads correctly
