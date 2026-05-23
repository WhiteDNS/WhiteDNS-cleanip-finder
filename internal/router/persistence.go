package router

import (
	"fmt"
	"os"
	"strings"
	"whitedns-go/internal/storage"
)

// SaveRoutes persists all cached routes to disk
func (r *Router) SaveRoutes(filePath string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lines []string

	for domain, cache := range r.domainCaches {
		cache.mu.RLock()
		for _, entry := range cache.Primary {
			lines = append(lines, fmt.Sprintf("%s %s", entry.Endpoint, domain))
		}
		for _, entry := range cache.Secondary {
			lines = append(lines, fmt.Sprintf("%s %s", entry.Endpoint, domain))
		}
		cache.mu.RUnlock()
	}

	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}

	return os.WriteFile(filePath, []byte(content), 0o666)
}

// LoadRoutes loads cached routes from disk
func (r *Router) LoadRoutes(filePath string) (int, error) {
	lines, err := storage.ReadTextLines(filePath)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		endpoint := parts[0]
		domain := parts[1]

		// Add to cache
		r.AddRouteToCache(domain, endpoint, 700.0, true)
		count++
	}

	return count, nil
}

// GetPoolStats returns statistics about the current route pool
func (r *Router) GetPoolStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	totalRoutes := 0
	totalEndpoints := make(map[string]bool)

	for _, cache := range r.domainCaches {
		cache.mu.RLock()
		totalRoutes += len(cache.Primary) + len(cache.Secondary)
		for _, entry := range cache.Primary {
			totalEndpoints[entry.Endpoint] = true
		}
		for _, entry := range cache.Secondary {
			totalEndpoints[entry.Endpoint] = true
		}
		cache.mu.RUnlock()
	}

	return map[string]interface{}{
		"total_routes":     totalRoutes,
		"unique_endpoints": len(totalEndpoints),
		"cached_domains":   len(r.domainCaches),
	}
}

// GetRoutesByEndpoint returns all domains using a specific endpoint
func (r *Router) GetRoutesByEndpoint(endpoint string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var domains []string
	for domain, cache := range r.domainCaches {
		cache.mu.RLock()
		for _, entry := range cache.Primary {
			if entry.Endpoint == endpoint {
				domains = append(domains, domain)
				break
			}
		}
		for _, entry := range cache.Secondary {
			if entry.Endpoint == endpoint {
				domains = append(domains, domain)
				break
			}
		}
		cache.mu.RUnlock()
	}
	return domains
}

// BanEndpoint removes an endpoint from all domains
func (r *Router) BanEndpoint(endpoint string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := 0
	for _, cache := range r.domainCaches {
		cache.mu.Lock()
		// Remove from primary
		newPrimary := []RouteEntry{}
		for _, entry := range cache.Primary {
			if entry.Endpoint != endpoint {
				newPrimary = append(newPrimary, entry)
			} else {
				count++
			}
		}
		cache.Primary = newPrimary

		// Remove from secondary
		newSecondary := []RouteEntry{}
		for _, entry := range cache.Secondary {
			if entry.Endpoint != endpoint {
				newSecondary = append(newSecondary, entry)
			} else {
				count++
			}
		}
		cache.Secondary = newSecondary
		cache.mu.Unlock()
	}

	return count
}

// GetEndpointsForDomain returns all endpoints for a domain
func (r *Router) GetEndpointsForDomain(domain string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cache, exists := r.domainCaches[domain]
	if !exists {
		return []string{}
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	var endpoints []string
	for _, entry := range cache.Primary {
		endpoints = append(endpoints, entry.Endpoint)
	}
	for _, entry := range cache.Secondary {
		endpoints = append(endpoints, entry.Endpoint)
	}

	return endpoints
}
