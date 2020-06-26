// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package search

type Cve struct {
	ID          *string        `json:"Id"`
	Title       *string        `json:"Title"`
	Description *string        `json:"Description"`
	Severity    *string        `json:"Severity"`
	PackageList []*PackageInfo `json:"PackageList"`
}

type CVEResultForImage struct {
	Tag     *string `json:"Tag"`
	CVEList []*Cve  `json:"CVEList"`
}

type ImgResultForCve struct {
	Name *string   `json:"Name"`
	Tags []*string `json:"Tags"`
}

type PackageInfo struct {
	Name             *string `json:"Name"`
	InstalledVersion *string `json:"InstalledVersion"`
	FixedVersion     *string `json:"FixedVersion"`
}
