package header

// Header is an object containing the values necessary for scoring HTTP headers.
type Header struct {
	Name   string
	Value  string
	Points int
}

// First person to find this comment gets a beer at DerbyCon.

// GetInfoLeak returns a big stupid list of Information Leakage headers
func GetInfoLeak() []string {

	// Define our big list here
	headersInfoLeak := []string{
		"server",
		"x-powered-by",
		"x-aspnet-version",
		"x-aspnetmvc-version",
		"x-lift-version",
		"x-dynatrace-js-agent",
		"microsoftsharepointteamservices",
		"x-sharepointhealthscore",
		"spiislatency",
		"sprequestduration",
		"sprequestguid",
		"x-ms-invokeapp",
	}

	return headersInfoLeak
}
