// goaudit: list print-family calls, logger calls and error/response sinks in a Go tree.
// usage: go run . <root> <out.json>
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Row struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Lang  string `json:"lang"`
	Kind  string `json:"kind"`
	Call  string `json:"call"`
	Level string `json:"level"`
	Src   string `json:"src"`
}

var (
	printFunc  = regexp.MustCompile(`^(fmt\.Print|fmt\.Printf|fmt\.Println|fmt\.Fprint|fmt\.Fprintf|fmt\.Fprintln|print|println|os\.Stdout\.Write|os\.Stderr\.Write|os\.Stdout\.WriteString|os\.Stderr\.WriteString|spew\.Dump|spew\.Printf|litter\.Dump|pp\.Print|pp\.Println)$`)
	levelMeth  = regexp.MustCompile(`^(?i)(debug|info|warn|warning|error|fatal|panic|trace|print|log)(f|ln|w|ctx|context)?$`)
	loggerRecv = regexp.MustCompile(`(?i)(log|logger|logging|zap|slog|logrus|zerolog|sugar|klog|glog)`)
	sinkFunc   = regexp.MustCompile(`^(errors\.New|fmt\.Errorf|errors\.Errorf|errors\.Wrap|errors\.Wrapf|errors\.WithMessage|errors\.WithMessagef|http\.Error|panic|status\.Errorf|status\.Error|status\.New|grpc\.Errorf|echo\.NewHTTPError|fiber\.NewError|gin\.Error)$`)
	sinkMeth   = regexp.MustCompile(`^(JSON|IndentedJSON|PureJSON|SecureJSON|AsciiJSON|JSONP|XML|YAML|TOML|ProtoBuf|AbortWithStatusJSON|AbortWithError|AbortWithStatus|String|Data|Encode|Write|WriteString|SendString|SendStatus|Send|Status|Error|Errorf|Render|HTML|Redirect|Blob|NoContent|JSONBlob|JSONPretty)$`)
	sinkRecv   = regexp.MustCompile(`^(c|ctx|w|rw|res|resp|writer|r|e|g|gc|fc|hc|ec|json\.NewEncoder\(\)|json\.NewEncoder\(w\)|render|response|out)$`)
	sinkHelper = regexp.MustCompile(`(?i)(respond|write|render|send|reply|return|handle|abort)(json|error|err|response|problem|failure|status|internal|bad)`)
	ws         = regexp.MustCompile(`\s+`)
)

func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		b := exprString(x.X)
		if b == "" {
			return x.Sel.Name
		}
		return b + "." + x.Sel.Name
	case *ast.CallExpr:
		return exprString(x.Fun) + "()"
	case *ast.IndexExpr:
		return exprString(x.X)
	case *ast.ParenExpr:
		return exprString(x.X)
	case *ast.StarExpr:
		return exprString(x.X)
	case *ast.TypeAssertExpr:
		return exprString(x.X)
	}
	return ""
}

func level(m string) string {
	l := strings.ToLower(m)
	for _, suf := range []string{"context", "ctx", "ln", "f", "w"} {
		if strings.HasSuffix(l, suf) && len(l) > len(suf)+2 {
			l = strings.TrimSuffix(l, suf)
			break
		}
	}
	if l == "warning" {
		l = "warn"
	}
	return l
}

func main() {
	root, out := os.Args[1], os.Args[2]
	fset := token.NewFileSet()
	rows := []Row{}
	skipDir := map[string]bool{"vendor": true, "testdata": true, "node_modules": true, ".git": true, "mocks": true, "mock": true}
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDir[info.Name()] || (strings.HasPrefix(info.Name(), ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := exprString(call.Fun)
			if callee == "" {
				return true
			}
			seg := string(src[fset.Position(call.Pos()).Offset:fset.Position(call.End()).Offset])
			seg = ws.ReplaceAllString(seg, " ")
			if len(seg) > 400 {
				seg = seg[:400]
			}
			row := Row{File: rel, Line: fset.Position(call.Pos()).Line, Lang: "go", Call: callee, Src: seg}
			last := callee
			recv := ""
			if i := strings.LastIndex(callee, "."); i >= 0 {
				last = callee[i+1:]
				recv = callee[:i]
			}
			switch {
			case printFunc.MatchString(callee):
				row.Kind = "print"
			case recv != "" && levelMeth.MatchString(last) && loggerRecv.MatchString(recv):
				row.Kind = "logger"
				row.Level = level(last)
			case callee == "log.Print" || callee == "log.Printf" || callee == "log.Println" || strings.HasPrefix(callee, "log.Fatal") || strings.HasPrefix(callee, "log.Panic"):
				row.Kind = "logger"
				row.Level = level(last)
			case sinkFunc.MatchString(callee):
				row.Kind = "sink"
			case recv != "" && sinkMeth.MatchString(last) && sinkRecv.MatchString(recv):
				row.Kind = "sink"
			case sinkHelper.MatchString(last):
				row.Kind = "sink"
			default:
				return true
			}
			rows = append(rows, row)
			return true
		})
		return nil
	})
	b, _ := json.MarshalIndent(rows, "", " ")
	os.WriteFile(out, b, 0644)
	os.Stdout.WriteString("rows " + strconv.Itoa(len(rows)) + "\n")
}
