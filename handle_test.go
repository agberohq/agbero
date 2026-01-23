package agbero

//func TestServer_HandleRequestWithWebRoute(t *testing.T) {
//	// Create a test server with a web route
//	root := t.TempDir()
//	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("INDEX"), 0644); err != nil {
//		t.Fatal(err)
//	}
//	if err := os.WriteFile(filepath.Join(root, "hello.html"), []byte("HELLO"), 0644); err != nil {
//		t.Fatal(err)
//	}
//
//	logger := ll.New("test")
//
//	// Create a minimal server with a web route
//	server := &Server{
//		logger: logger,
//		hostManager: &mockHostManager{
//			hosts: map[string]*woos.Host{
//				"static.com": {
//					Domains: []string{"static.com"},
//					Routes: []woos.Route{
//						{
//							Path: "/",
//							Web: cnfs.Web{
//								Root:  cnfs.WebRoot(root),
//								Index: "index.html",
//							},
//						},
//					},
//				},
//			},
//		},
//	}
//
//	// Test index
//	req := httptest.NewRequest("GET", "http://static.com/", nil)
//	rr := httptest.NewRecorder()
//	server.handleRequest(rr, req)
//
//	if rr.Code != 200 {
//		t.Fatalf("expected 200, got %d", rr.Code)
//	}
//	if rr.Body.String() != "INDEX" {
//		t.Fatalf("expected INDEX, got %q", rr.Body.String())
//	}
//
//	// Test file
//	req = httptest.NewRequest("GET", "http://static.com/hello.html", nil)
//	rr = httptest.NewRecorder()
//	server.handleRequest(rr, req)
//
//	if rr.Code != 200 {
//		t.Fatalf("expected 200, got %d", rr.Code)
//	}
//	if rr.Body.String() != "HELLO" {
//		t.Fatalf("expected HELLO, got %q", rr.Body.String())
//	}
//}
//
//func TestServer_HandleRequest_MethodNotAllowed(t *testing.T) {
//	root := t.TempDir()
//	logger := ll.New("test")
//
//	server := &Server{
//		logger: logger,
//		hostManager: &mockHostManager{
//			hosts: map[string]*woos.Host{
//				"static.com": {
//					Domains: []string{"static.com"},
//					Routes: []woos.Route{
//						{
//							Path: "/",
//							Web: &cnfs.Web{
//								Root: cnfs.WebRoot(root),
//							},
//						},
//					},
//				},
//			},
//		},
//	}
//
//	req := httptest.NewRequest("POST", "http://static.com/", nil)
//	rr := httptest.NewRecorder()
//	server.handleRequest(rr, req)
//
//	if rr.Code != http.StatusMethodNotAllowed {
//		t.Fatalf("expected 405, got %d", rr.Code)
//	}
//}
//
//// Mock host manager for testing
//type mockHostManager struct {
//	hosts map[string]*woos.Host
//}
//
//func (m *mockHostManager) Get(hostname string) *woos.Host {
//	return m.hosts[hostname]
//}
//
//func (m *mockHostManager) LoadAll() (map[string]*woos.Host, error) {
//	return m.hosts, nil
//}
//
//func (m *mockHostManager) Watch() error                                           { return nil }
//func (m *mockHostManager) Close() error                                           { return nil }
//func (m *mockHostManager) Changed() <-chan struct{}                               { return nil }
//func (m *mockHostManager) ReloadFull()                                            {}
//func (m *mockHostManager) UpdateGossipNode(nodeID, host string, route woos.Route) {}
//func (m *mockHostManager) RemoveGossipNode(nodeID string)                         {}
//func (m *mockHostManager) RouteExists(host, path string) bool                     { return false }
//func (m *mockHostManager) ResetNodeFailures(nodeName string)                      {}
