@RestController
class C {
  @GetMapping("/u/{id}")
  public String get(@PathVariable String id, @RequestParam String q) {
    String sql = "SELECT * FROM u WHERE n = '" + q + "'";
    return jdbc.queryForObject(sql, String.class);      // VULN sqli (annotated source)
  }
  @PostMapping("/run")
  public void run(@RequestParam String host) {
    Runtime.getRuntime().exec("ping " + host);          // VULN command_injection
  }
  @GetMapping("/safe")
  public String safe(@RequestParam String n) {
    int id = Integer.parseInt(n);                        // SAFE: parseInt
    return jdbc.queryForObject("SELECT * FROM t WHERE id = " + id, String.class);
  }
  @GetMapping("/file")
  public void file(@RequestParam String name) throws Exception {
    new java.io.FileInputStream("/data/" + name);        // VULN path_traversal
  }
}
