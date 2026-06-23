// Package main
package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================================
// WEBSOCKET
// ============================================================================
const wsMaxInboundMessageSize int64 = 1024

func (h *WSHub) run() {
	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = true
			n := len(h.clients)
			h.mu.Unlock()

			go c.writePump()
			go c.readPump(h)

			debugLog("WS", "", fmt.Sprintf("Client connected (total: %d)", n))

		case c := <-h.unregister:
			removed := false
			n := 0

			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				removed = true
				n = len(h.clients)

				func() {
					defer func() { _ = recover() }()
					c.closeSend()
				}()
			}
			h.mu.Unlock()

			if removed {
				debugLog("WS", "", fmt.Sprintf("Client disconnected (total: %d)", n))
				_ = c.conn.Close()
			}

		case msg := <-h.broadcast:
			h.mu.RLock()
			if len(h.clients) == 0 {
				h.mu.RUnlock()
				continue
			}

			clients := make([]*WSClient, 0, len(h.clients))
			for c := range h.clients {
				clients = append(clients, c)
			}
			h.mu.RUnlock()

			h.broadcastToClients(clients, msg)
		}
	}
}

func (h *WSHub) broadcastToClients(clients []*WSClient, msg WSMessage) {
	go func() {
		var wg sync.WaitGroup
		for _, c := range clients {
			wg.Add(1)
			go func(client *WSClient) {
				defer wg.Done()
				select {
				case client.send <- msg:
				default:
					debugLog("WS", "", "client send queue full - disconnecting")
					select {
					case h.unregister <- client:
					default:
						h.forceRemoveClient(client)
					}
				}
			}(c)
		}
		wg.Wait()
	}()
}

func (c *WSClient) writePump() {
	ticker := time.NewTicker(WSPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			return

		case msg, ok := <-c.send:
			if !ok {
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
			if err := c.conn.WriteJSON(msg); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *WSClient) readPump(h *WSHub) {
	defer func() {
		select {
		case h.unregister <- c:
		default:
			h.forceRemoveClient(c)
		}
	}()

	c.conn.SetReadLimit(wsMaxInboundMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(WSPongTimeout))
		return nil
	})

	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (c *WSClient) closeSend() {
	c.closeOnce.Do(func() {
		close(c.send)
	})
}

func broadcastUpdate(updateType string, data any) {
	msg := WSMessage{Type: updateType, Data: data}
	select {
	case wsHub.broadcast <- msg:
	default:
		debugLog("WS", "", "broadcast queue full - dropping message")
	}
}

func broadcastNotification(message, level string) {
	if level == "" {
		level = "info"
	}
	broadcastUpdate("notification", map[string]string{
		"message": message,
		"level":   level,
	})
}

func (h *WSHub) forceRemoveClient(c *WSClient) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		func() {
			defer func() { _ = recover() }()
			c.closeSend()
		}()
	}
	h.mu.Unlock()
	_ = c.conn.Close()
}
