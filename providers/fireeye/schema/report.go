package schema

// FireeyeReportIndexItem one item in array returned on /report/index
// we only want the reportID so we can use it to get /report/{reportID}
type FireeyeReportIndexItem struct {
	ReportID string `json:"reportId"`
}

// FireeyeReportWrapper struct
type FireeyeReportWrapper struct {
	Report FireeyeReport `json:"report"`
}

// FireeyeReport struct
type FireeyeReport struct {
	Audience            []string                  `json:"audience"`
	Copyright           string                    `json:"copyright"`
	CveIDs              *FireeyeReportCveIDs      `json:"cveIds"`
	ExecSummary         string                    `json:"execSummary"`
	IntelligenceType    string                    `json:"intelligenceType"`
	PublishDate         string                    `json:"publishDate"`
	ReportID            string                    `json:"reportId"`
	ReportType          string                    `json:"reportType"`
	TagSection          *FireeyeReportTagSection  `json:"tagSection"`
	ThreatScape         *FireeyeReportThreatScape `json:"ThreatScape"`
	Title               string                    `json:"title"`
	Version             string                    `json:"version"`
	Version1PublishDate string                    `json:"version1PublishDate"`
}

// FireeyeReportCveIDs struct
type FireeyeReportCveIDs struct {
	CveID []string `json:"cveId"`
}

// FireeyeReportTagSection struct
type FireeyeReportTagSection struct {
	Files    *FireeyeReportFiles    `json:"files"`
	Main     *FireeyeReportMain     `json:"main"`
	Networks *FireeyeReportNetworks `json:"networks"`
}

// FireeyeReportThreatScape struct
type FireeyeReportThreatScape struct {
	Product []string `json:"product"`
}

// FireeyeReportFiles struct
type FireeyeReportFiles struct {
	File []*FireeyeReportFile `json:"file"`
}

// FireeyeReportFile struct
type FireeyeReportFile struct {
	Sha1       string `json:"sha1"`
	Identifier string `json:"identifier"`
	Actor      string `json:"actor"`
	FileName   string `json:"fileName"`
	FileSize   string `json:"fileSize"`
	ActorID    string `json:"actorId"`
	Sha256     string `json:"sha256"`
	Type       string `json:"type"`
	Md5        string `json:"md5"`
}

// FireeyeReportMain struct
type FireeyeReportMain struct {
	Actors               *FireeyeReportActors               `json:"actors"`
	AffectedIndustries   *FireeyeReportAffectedIndustries   `json:"affectedIndustries"`
	IntendedEffects      *FireeyeReportIntendedEffects      `json:"intendedEffects"`
	MalwareFamilies      *FireeyeReportMalwareFamilies      `json:"malwareFamilies"`
	Motivations          *FireeyeReportMotivations          `json:"motivations"`
	SourceGeographies    *FireeyeReportSourceGeographies    `json:"sourceGeographies"`
	TargetedInformations *FireeyeReportTargetedInformations `json:"targetedInformations"`
	TargetGeographies    *FireeyeReportTargetGeographies    `json:"targetGeographies"`
	Ttps                 *FireeyeReportTtps                 `json:"ttps"`
}

// FireeyeReportActors struct
type FireeyeReportActors struct {
	Actor []*FireeyeReportActor `json:"actor"`
}

// FireeyeReportActor struct
type FireeyeReportActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// FireeyeReportNetworks struct
type FireeyeReportNetworks struct {
	Networks []*FireeyeReportNetwork `json:"network"`
}

// FireeyeReportNetwork struct
type FireeyeReportNetwork struct {
	URL         string `json:"url"`
	NetworkType string `json:"networkType"`
	Identifier  string `json:"identifier"`
	Actor       string `json:"actor"`
	ActorID     string `json:"actorId"`
	Domain      string `json:"domain"`
}

// FireeyeReportMotivations struct
type FireeyeReportMotivations struct {
	Motivation []string `json:"motivation"`
}

// FireeyeReportSourceGeographies struct
type FireeyeReportSourceGeographies struct {
	SourceGeography []string `json:"sourceGeography"`
}

// FireeyeReportAffectedIndustries struct
type FireeyeReportAffectedIndustries struct {
	AffectedIndustry []string `json:"affectedIndustry"`
}

// FireeyeReportIntendedEffects struct
type FireeyeReportIntendedEffects struct {
	IntendedEffect []string `json:"intendedEffect"`
}

// FireeyeReportTtps struct
type FireeyeReportTtps struct {
	Ttp []string `json:"ttp"`
}

// FireeyeReportTargetGeographies struct
type FireeyeReportTargetGeographies struct {
	TargetGeography []string `json:"targetGeography"`
}

// FireeyeReportTargetedInformations struct
type FireeyeReportTargetedInformations struct {
	TargetedInformation []string `json:"targetedInformation"`
}

// FireeyeReportMalwareFamilies struct
type FireeyeReportMalwareFamilies struct {
	MalwareFamily []*FireeyeReportMalwareFamily `json:"malwareFamily"`
}

// FireeyeReportMalwareFamily struct
type FireeyeReportMalwareFamily struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
