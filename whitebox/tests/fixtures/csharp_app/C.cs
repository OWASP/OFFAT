[ApiController]
public class C {
  [HttpGet("/u")]
  public string Get([FromQuery] string q) {
    var sql = "SELECT * FROM u WHERE n = '" + q + "'";
    return new SqlCommand(sql, conn).ExecuteReader();        // VULN sqli
  }
  [HttpGet("/file")]
  public string Read([FromQuery] string name) {
    return File.ReadAllText("/data/" + name);                // VULN path_traversal
  }
  [HttpGet("/safe")]
  public string Safe([FromQuery] string n) {
    int id = int.Parse(n);                                   // SAFE: int.Parse
    return new SqlCommand("SELECT * FROM t WHERE id = " + id, conn).ExecuteReader();
  }
}
