package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"

	repo "github.com/CWE-CAPEC/REST-API-wg/json_repo"
)

// ── minimal structs for building indices ──────────────────────────────────────

type relatedWeakness struct {
	Nature string `json:"Nature"`
	CweID  string `json:"CweID"`
	ViewID string `json:"ViewID"`
}

type relation struct {
	Type string `json:"Type"`
	ID   string `json:"ID"`
}

type childEntry struct {
	ID     string
	ViewID string
}

// ── server ────────────────────────────────────────────────────────────────────

type server struct {
	weaknesses map[string]json.RawMessage
	categories map[string]json.RawMessage
	views      map[string]json.RawMessage
	version    json.RawMessage
	childrenOf map[string][]childEntry // parentID -> children
}

func newServer() *server {
	s := &server{
		weaknesses: make(map[string]json.RawMessage),
		categories: make(map[string]json.RawMessage),
		views:      make(map[string]json.RawMessage),
		childrenOf: make(map[string][]childEntry),
	}
	s.load()
	return s
}

func (s *server) load() {
	// version
	if data, err := repo.Repo.ReadFile("cwev.json"); err == nil {
		s.version = json.RawMessage(data)
	}

	// weaknesses
	entries, _ := fs.ReadDir(repo.Repo, "W")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		data, err := repo.Repo.ReadFile("W/" + e.Name())
		if err != nil {
			continue
		}
		s.weaknesses[id] = json.RawMessage(data)

		// build reverse children index
		var w struct {
			RelatedWeaknesses []relatedWeakness `json:"RelatedWeaknesses"`
		}
		if json.Unmarshal(data, &w) == nil {
			for _, rel := range w.RelatedWeaknesses {
				if rel.Nature == "ChildOf" {
					s.childrenOf[rel.CweID] = append(s.childrenOf[rel.CweID], childEntry{id, rel.ViewID})
				}
			}
		}
	}

	// categories
	entries, _ = fs.ReadDir(repo.Repo, "C")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		data, _ := repo.Repo.ReadFile("C/" + e.Name())
		s.categories[id] = json.RawMessage(data)
	}

	// views
	entries, _ = fs.ReadDir(repo.Repo, "V")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		data, _ := repo.Repo.ReadFile("V/" + e.Name())
		s.views[id] = json.RawMessage(data)
	}

	log.Printf("loaded: %d weaknesses, %d categories, %d views",
		len(s.weaknesses), len(s.categories), len(s.views))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *server) lookup(id string) (json.RawMessage, string, bool) {
	if d, ok := s.weaknesses[id]; ok {
		return d, "Weakness", true
	}
	if d, ok := s.categories[id]; ok {
		return d, "Category", true
	}
	if d, ok := s.views[id]; ok {
		return d, "View", true
	}
	return nil, "", false
}

func (s *server) parents(id, viewFilter string) ([]relation, bool) {
	data, _, ok := s.lookup(id)
	if !ok {
		return nil, false
	}
	var w struct {
		RelatedWeaknesses []relatedWeakness `json:"RelatedWeaknesses"`
	}
	json.Unmarshal(data, &w) //nolint
	var result []relation
	for _, rel := range w.RelatedWeaknesses {
		if rel.Nature != "ChildOf" {
			continue
		}
		if viewFilter != "" && rel.ViewID != viewFilter {
			continue
		}
		_, typ, _ := s.lookup(rel.CweID)
		if typ == "" {
			typ = "Weakness"
		}
		result = append(result, relation{Type: typ, ID: rel.CweID})
	}
	if result == nil {
		result = []relation{}
	}
	return result, true
}

func (s *server) children(id, viewFilter string) ([]relation, bool) {
	if _, _, ok := s.lookup(id); !ok {
		return nil, false
	}
	var result []relation
	for _, c := range s.childrenOf[id] {
		if viewFilter != "" && c.ViewID != viewFilter {
			continue
		}
		_, typ, _ := s.lookup(c.ID)
		if typ == "" {
			typ = "Weakness"
		}
		result = append(result, relation{Type: typ, ID: c.ID})
	}
	if result == nil {
		result = []relation{}
	}
	return result, true
}

// ── router ────────────────────────────────────────────────────────────────────

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	parts := strings.Split(strings.Trim(path, "/"), "/")

	if len(parts) < 2 || parts[0] != "cwe" {
		http.NotFound(w, r)
		return
	}

	switch {
	// GET /api/v1/cwe/version
	case len(parts) == 2 && parts[1] == "version":
		if s.version == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.version) //nolint

	// GET /api/v1/cwe/weakness/{id(s)}
	case len(parts) == 3 && parts[1] == "weakness":
		s.handleEntries(w, r, parts[2], s.weaknesses)

	// GET /api/v1/cwe/category/{id(s)}
	case len(parts) == 3 && parts[1] == "category":
		s.handleEntries(w, r, parts[2], s.categories)

	// GET /api/v1/cwe/view/{id(s)}
	case len(parts) == 3 && parts[1] == "view":
		s.handleEntries(w, r, parts[2], s.views)

	// GET /api/v1/cwe/{id}/parents
	case len(parts) == 3 && parts[2] == "parents":
		view := r.URL.Query().Get("view")
		res, ok := s.parents(parts[1], view)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, res)

	// GET /api/v1/cwe/{id}/children
	case len(parts) == 3 && parts[2] == "children":
		view := r.URL.Query().Get("view")
		res, ok := s.children(parts[1], view)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, res)

	// GET /api/v1/cwe/{id}/descendants
	case len(parts) == 3 && parts[2] == "descendants":
		view := r.URL.Query().Get("view")
		if _, _, ok := s.lookup(parts[1]); !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, s.descendants(parts[1], view))

	// GET /api/v1/cwe/{id}/ancestors
	case len(parts) == 3 && parts[2] == "ancestors":
		view := r.URL.Query().Get("view")
		if _, _, ok := s.lookup(parts[1]); !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, s.ancestors(parts[1], view))

	// GET /api/v1/cwe/{id(s)}  – metadata (type info)
	case len(parts) == 2:
		s.handleInfo(w, r, parts[1])

	default:
		http.NotFound(w, r)
	}
}

// handleEntries serves weakness/category/view endpoints (single, list, or "all")
func (s *server) handleEntries(w http.ResponseWriter, r *http.Request, idsStr string, store map[string]json.RawMessage) {
	if idsStr == "all" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[")) //nolint
		first := true
		for _, v := range store {
			if !first {
				w.Write([]byte(",")) //nolint
			}
			w.Write(v) //nolint
			first = false
		}
		w.Write([]byte("]\n")) //nolint
		return
	}

	ids := strings.Split(idsStr, ",")
	result := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		d, ok := store[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		result = append(result, d)
	}
	writeJSON(w, http.StatusOK, result)
}

// handleInfo returns [{id, type}] for each requested ID
func (s *server) handleInfo(w http.ResponseWriter, r *http.Request, idsStr string) {
	ids := strings.Split(idsStr, ",")
	result := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		_, typ, ok := s.lookup(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		result = append(result, map[string]string{"id": id, "type": typ})
	}
	writeJSON(w, http.StatusOK, result)
}

// descendants returns all descendants of id via BFS
func (s *server) descendants(id, viewFilter string) []relation {
	var result []relation
	visited := map[string]bool{}
	queue := []string{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range s.childrenOf[cur] {
			if viewFilter != "" && c.ViewID != viewFilter {
				continue
			}
			if visited[c.ID] {
				continue
			}
			visited[c.ID] = true
			_, typ, _ := s.lookup(c.ID)
			if typ == "" {
				typ = "Weakness"
			}
			result = append(result, relation{Type: typ, ID: c.ID})
			queue = append(queue, c.ID)
		}
	}
	if result == nil {
		result = []relation{}
	}
	return result
}

// ancestors returns all ancestors of id via BFS
func (s *server) ancestors(id, viewFilter string) []relation {
	var result []relation
	visited := map[string]bool{}
	queue := []string{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		pp, ok := s.parents(cur, viewFilter)
		if !ok {
			continue
		}
		for _, p := range pp {
			if visited[p.ID] {
				continue
			}
			visited[p.ID] = true
			result = append(result, p)
			queue = append(queue, p.ID)
		}
	}
	if result == nil {
		result = []relation{}
	}
	return result
}

// ── entry point ───────────────────────────────────────────────────────────────

func main() {
	s := newServer()
	log.Println("CWE API listening on :8080  →  http://localhost:8080/api/v1/cwe/version")
	if err := http.ListenAndServe(":8080", s); err != nil {
		log.Fatal(err)
	}
}
