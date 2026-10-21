package main

import "github.com/gin-gonic/gin"

func rawQuery(sql string) { db.Query(sql) } // sink, reached interprocedurally

func lookupByName(name string) {
	rawQuery("SELECT * FROM u WHERE n = '" + name + "'") // VULN sqli (from /gin-search)
}

func ginSearch(c *gin.Context) {
	lookupByName(c.Query("name"))
}

func ginRoutes() {
	rt := gin.Default()
	rt.GET("/gin-search", ginSearch)
}
