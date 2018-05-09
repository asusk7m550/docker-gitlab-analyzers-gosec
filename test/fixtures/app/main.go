package main

import (
	"html/template"
	"math/big"
	"os"
)

const tmpl = ""

func main() {
	a := "something from another place"
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		"Body":  template.HTML(a),
	}
	t.Execute(os.Stdout, v)
	z := new(big.Int)
	x := new(big.Int)
	x = x.SetUint64(2)
	y := new(big.Int)
	y = y.SetUint64(4)
	m := new(big.Int)
	m = m.SetUint64(0)
	z = z.Exp(x, y, m)
}
