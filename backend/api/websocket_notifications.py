"""
WebSocket Notification System for Real-Time Updates

Provides WebSocket endpoint for pushing real-time notifications to connected clients.
Used for new email notifications, system alerts, etc.
"""

from typing import Dict, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from backend.api.auth import _decode_token, _get_secret_and_exp
import json
import asyncio


router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time notifications"""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, username: str):
        """Add a new connection for a user"""
        await websocket.accept()
        async with self.lock:
            if username not in self.active_connections:
                self.active_connections[username] = set()
            self.active_connections[username].add(websocket)
        print(f"[websocket] User {username} connected (total: {len(self.active_connections[username])})")

    async def disconnect(self, websocket: WebSocket, username: str):
        """Remove a connection"""
        async with self.lock:
            if username in self.active_connections:
                self.active_connections[username].discard(websocket)
                if not self.active_connections[username]:
                    del self.active_connections[username]
        print(f"[websocket] User {username} disconnected")

    async def send_personal_message(self, message: dict, username: str):
        """Send a message to a specific user (all their connections)"""
        if username not in self.active_connections:
            return

        disconnected = []
        for connection in list(self.active_connections.get(username, [])):
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"[websocket] Error sending to {username}: {e}")
                disconnected.append(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self.lock:
                for conn in disconnected:
                    self.active_connections[username].discard(conn)
                if not self.active_connections[username]:
                    del self.active_connections[username]

    async def broadcast(self, message: dict, roles: list = None):
        """
        Broadcast a message to all connected users (optionally filtered by role)

        Note: Since we don't track roles per connection, this sends to all users.
        For role-based filtering, you'd need to store role info with each connection.
        """
        disconnected = []
        for username, connections in list(self.active_connections.items()):
            for connection in list(connections):
                try:
                    await connection.send_json(message)
                except Exception as e:
                    print(f"[websocket] Error broadcasting to {username}: {e}")
                    disconnected.append((username, connection))

        # Clean up disconnected clients
        if disconnected:
            async with self.lock:
                for username, conn in disconnected:
                    if username in self.active_connections:
                        self.active_connections[username].discard(conn)
                        if not self.active_connections[username]:
                            del self.active_connections[username]


# Global connection manager instance
manager = ConnectionManager()


async def verify_websocket_token(websocket: WebSocket) -> str:
    """
    Verify JWT token from WebSocket connection

    Token can be sent via:
    1. Query parameter: ?token=xxx
    2. In the first message: {"token": "xxx"}
    """
    # Try query parameter first
    token = websocket.query_params.get("token")

    if not token:
        # Try to receive token from first message
        try:
            data = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
            token = data.get("token")
        except asyncio.TimeoutError:
            raise Exception("Token not provided within timeout")
        except Exception as e:
            raise Exception(f"Failed to receive token: {e}")

    if not token:
        raise Exception("No token provided")

    # Validate token
    cfg = _get_secret_and_exp()
    try:
        payload = _decode_token(token, cfg["secret"])
        if payload.get("type") != "access":
            raise Exception("Invalid token type")
        return payload.get("sub", "unknown")
    except Exception as e:
        raise Exception(f"Invalid token: {e}")


@router.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    """
    WebSocket endpoint for real-time notifications

    Connection flow:
    1. Client connects with JWT token (query param or first message)
    2. Server validates token and adds connection to manager
    3. Server can push notifications to client
    4. Client receives JSON messages with structure:
       {"type": "new_email", "subject": "...", "created_at": "..."}
    """
    username = None
    try:
        # Authenticate
        username = await verify_websocket_token(websocket)

        # Add to connection manager
        await manager.connect(websocket, username)

        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "message": f"Connected as {username}",
            "timestamp": asyncio.get_event_loop().time()
        })

        # Keep connection alive and handle incoming messages
        while True:
            try:
                data = await websocket.receive_json()
                # Handle ping/pong for keepalive
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break
            except Exception as e:
                print(f"[websocket] Error receiving message from {username}: {e}")
                break

    except Exception as e:
        print(f"[websocket] Connection error: {e}")
        try:
            await websocket.close(code=1008, reason=str(e))
        except Exception:
            pass
    finally:
        if username:
            await manager.disconnect(websocket, username)


async def notify_new_email(email_data: dict, username: str = None):
    """
    Notify about a new email

    Args:
        email_data: Dict with keys: subject, sender, created_at, id, etc.
        username: If provided, notify only this user. Otherwise broadcast to all.
    """
    message = {
        "type": "new_email",
        "subject": email_data.get("subject", ""),
        "sender": email_data.get("sender", ""),
        "created_at": email_data.get("created_at", ""),
        "id": email_data.get("id", ""),
        "final_decision": email_data.get("final_decision", ""),
    }

    if username:
        await manager.send_personal_message(message, username)
    else:
        await manager.broadcast(message)


async def notify_system_alert(message: str, level: str = "info", username: str = None):
    """
    Send a system alert notification

    Args:
        message: Alert message
        level: "info", "warning", "error", "success"
        username: If provided, notify only this user. Otherwise broadcast.
    """
    notification = {
        "type": "system_alert",
        "message": message,
        "level": level,
        "timestamp": asyncio.get_event_loop().time()
    }

    if username:
        await manager.send_personal_message(notification, username)
    else:
        await manager.broadcast(notification)
