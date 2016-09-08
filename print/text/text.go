package text

import "fmt"
import "os"
import "text/tabwriter"
import "github.com/dacoursey/skinner/header"

func main() {
	// Nothing to see here.
}

// PrintScore is used to print only the point value of the found headers.
func PrintScore(score int, target string) {

	// Let's print some pretty stuff.
	fmt.Printf("\n\n")
	fmt.Println("**************************************************")
	fmt.Println("* Scoring")
	fmt.Println("**************************************************")
	fmt.Printf("\n")

	fmt.Printf("Target: %v\n", target)
	fmt.Printf("Total Score: %v\n", score)
}

// PrintAll is used to print all results for one host in a formatted text table.
func PrintAll(score int, headersPresent []header.Header, headersUnknown []header.Header) {

	// Let's print some pretty stuff.
	fmt.Printf("\n\n")
	fmt.Println("||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
	fmt.Println("* Scoring")
	fmt.Println("||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
	fmt.Printf("\n")

	fmt.Printf("Total Score: %v\n", score)

	// Print the raw list of headers.
	w := new(tabwriter.Writer)

	fmt.Printf("\n")
	fmt.Println("**************************************************")
	fmt.Println("* Scored Headers")
	fmt.Println("**************************************************")
	fmt.Printf("\n")

	// ToDo: Come back and clean this up with column alignment.
	for i := range headersPresent {
		if headersPresent[i].Points != 0 {
			h := headersPresent[i].Name
			v := headersPresent[i].Value
			p := headersPresent[i].Points

			// Print out in tab separated columns (hopefully)
			w.Init(os.Stdout, 40, 8, 0, '\t', 0)
			fmt.Fprintf(w, "Header: %v\tValue: %v\tPoints: %v\t\n", h, v, p)
			w.Flush()
		}
	}

	fmt.Printf("\n")
	fmt.Println("**************************************************")
	fmt.Println("* Unknown Headers")
	fmt.Println("* Evaluate the following headers for information leakage.")
	fmt.Println("**************************************************")
	fmt.Printf("\n")

	for i := range headersUnknown {
		h := headersUnknown[i].Name
		v := headersUnknown[i].Value
		//fmt.Printf("Header: %v \t\t Value: %v\n", h, v)
		// Print out in tab separated columns (hopefully)
		w.Init(os.Stdout, 40, 8, 0, '\t', 0)
		fmt.Fprintf(w, "Header: %v\tValue: %v\t\n", h, v)
		w.Flush()
	}

	// Let's print some more pretty stuff.
	fmt.Printf("\n")
	fmt.Println("**************************************************")
	fmt.Println("**************************************************")
}
