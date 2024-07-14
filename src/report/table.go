package report

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
)

var (
	FailColor    = tablewriter.Colors{tablewriter.FgHiRedColor, tablewriter.Bold}
	SuccessColor = tablewriter.Colors{tablewriter.FgHiGreenColor, tablewriter.Bold}
	NormalColor  = tablewriter.Colors{tablewriter.Normal}
)

type RichRow struct {
	Row      []string
	RowColor []tablewriter.Colors
}

func apiTableToTableRow(apiTest *tgen.ApiTest) ([]string, []tablewriter.Colors) {
	var vulnerable, dataleak, statusCode, errStr string
	var vulnerableColor, dataleakColor tablewriter.Colors

	if apiTest.IsVulnerable {
		vulnerable = "YES!"
		vulnerableColor = FailColor
	} else {
		vulnerable = "NO"
		vulnerableColor = SuccessColor
	}
	if apiTest.IsDataLeak {
		dataleak = "YES!"
		dataleakColor = FailColor
	} else {
		dataleak = "NO"
		dataleakColor = SuccessColor
	}

	if apiTest.Response.Response != nil {
		statusCode = strconv.Itoa(apiTest.Response.Response.StatusCode)
	} else {
		statusCode = "-"
	}

	if apiTest.Response.Error != nil {
		errStr = apiTest.Response.Error.Error()
	} else {
		errStr = "-"
	}

	row := []string{
		apiTest.Request.Method,
		apiTest.Path,
		statusCode,
		errStr,
		apiTest.TestName,
		vulnerable,
		dataleak,
	}

	rowColors := []tablewriter.Colors{
		NormalColor,
		NormalColor,
		NormalColor,
		NormalColor,
		NormalColor,
		vulnerableColor,
		dataleakColor,
	}

	return row, rowColors
}

func Table(apiTest []*tgen.ApiTest) {
	// Get terminal size
	width, _, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Error getting terminal size:", err)
		return
	}

	// Create table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(true)
	table.SetAutoFormatHeaders(true)
	// table.SetAutoMergeCells(true)
	table.SetRowLine(true)

	table.SetHeaderLine(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetBorder(true)

	headers := []string{
		"Method",
		"Endpoint Path",
		"Status Code",
		"Error",
		"Test Name",
		"Vulnerable",
		"Data Leak",
	}
	table.SetHeader(headers)

	// Set header color
	colors := make([]tablewriter.Colors, len(headers))
	for i := range headers {
		colors[i] = tablewriter.Colors{tablewriter.FgHiWhiteColor}
	}
	table.SetHeaderColor(colors...)

	// Set the table width to the terminal width
	table.SetColWidth(width / len(headers))

	var wg sync.WaitGroup
	var mutex sync.Mutex
	for _, apiTest := range apiTest {
		wg.Add(1)

		go func(data *tgen.ApiTest) {
			defer wg.Done()

			// Lock before modifying table
			mutex.Lock()
			defer mutex.Unlock()

			row, colors := apiTableToTableRow(data)
			table.Rich(row, colors)
		}(apiTest)
	}

	wg.Wait()

	table.Render()
}