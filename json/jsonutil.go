package json

import (
	"encoding/json"
	"fmt"
	"io"
)


func PrintJsonStruct(writer io.Writer, js interface{}) {
	b, e := json.MarshalIndent(js, "  ", "  ")
	if e != nil {
		fmt.Fprintln(writer,e)
	} else {
		writer.Write(b)
		fmt.Fprintln(writer, "")
	}

}