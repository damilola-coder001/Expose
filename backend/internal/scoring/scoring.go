package scoring

import (
	"math"

	"github.com/expose/expose-backend/internal/models"
)

var severityDeductions = map[models.Severity]int{
	models.SeverityCritical: 25,
	models.SeverityHigh:     15,
	models.SeverityMedium:   8,
	models.SeverityLow:      3,
	models.SeverityInfo:     0,
}

type categoryGroup struct {
	categories map[models.Category]bool
	weight     int
}

var categoryMappings = map[string]categoryGroup{
	"Transport & Cryptography": {
		categories: map[models.Category]bool{
			models.CategoryCryptography:      true,
			models.CategoryTransportSecurity: true,
		},
		weight: 30,
	},
	"HTTP Security Headers": {
		categories: map[models.Category]bool{
			models.CategoryTransportSecurity: true,
		},
		weight: 25,
	},
	"Domain & Email Integrity": {
		categories: map[models.Category]bool{
			models.CategoryDNSConfiguration: true,
			models.CategoryEmailSecurity:    true,
		},
		weight: 20,
	},
	"Cookie & Session Hygiene": {
		categories: map[models.Category]bool{
			models.CategoryCookieSecurity: true,
		},
		weight: 15,
	},
	"Public Information & Metadata": {
		categories: map[models.Category]bool{
			models.CategorySecurityMetadata:     true,
			models.CategoryInformationDisclosure: true,
		},
		weight: 10,
	},
}

// DefaultNotAssessedAreas lists explicitly unassessed security boundaries.
var DefaultNotAssessedAreas = []models.NotAssessedArea{
	{
		Area:   "Authentication & Session Management",
		Reason: "Requires authenticated credentials, user accounts, and active session tokens.",
		Explanation: "External unauthenticated scanning cannot evaluate password complexity enforcement, " +
			"credential stuffing defenses, MFA workflows, or session hijacking vulnerabilities.",
	},
	{
		Area:   "Business Logic & Workflow Integrity",
		Reason: "Requires context on business workflows, transaction logic, and multi-tenant authorization matrices.",
		Explanation: "Logic flaws such as Insecure Direct Object References (IDOR), price manipulation, and race conditions " +
			"cannot be observed from passive external surface analysis.",
	},
	{
		Area:   "Active Code Injection (SQLi, RCE, Command Injection)",
		Reason: "Invasive attack payloads are strictly prohibited in safe external intelligence assessments.",
		Explanation: "Expose operates safely without sending destructive or intrusive payloads. Active exploit testing " +
			"requires explicit authorization and dedicated penetration testing engagements.",
	},
	{
		Area:   "Internal Infrastructure & Private VPC",
		Reason: "Protected behind edge firewalls, NAT gateways, and private network segmentation.",
		Explanation: "Internal microservices, private databases, and cloud metadata services cannot be directly observed " +
			"from the public internet.",
	},
	{
		Area:   "Source Code & Repository Dependencies",
		Reason: "Requires direct access to source code repositories, lockfiles, and CI/CD pipelines.",
		Explanation: "Public web endpoints only expose runtime responses, not underlying repository source code or build artifacts.",
	},
}

// CalculateLetterGrade maps 0-100 score to letter grade.
func CalculateLetterGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// CalculateScoreCard evaluates all findings to compute 0-100 posture score.
func CalculateScoreCard(findings []models.Finding) *models.ScoreCard {
	var confirmed []models.Finding
	var observed []models.Finding

	for _, f := range findings {
		if f.Status == models.StatusConfirmed {
			confirmed = append(confirmed, f)
		} else if f.Status == models.StatusObserved {
			observed = append(observed, f)
		}
	}

	categoryScores := make(map[string]models.CategoryScore)
	var totalWeightedScore float64

	for groupName, groupCfg := range categoryMappings {
		var groupConfirmed []models.Finding
		var allGroupFindings []models.Finding

		for _, f := range findings {
			if groupCfg.categories[f.Category] {
				allGroupFindings = append(allGroupFindings, f)
				if f.Status == models.StatusConfirmed {
					groupConfirmed = append(groupConfirmed, f)
				}
			}
		}

		deduction := 0
		for _, f := range groupConfirmed {
			deduction += severityDeductions[f.Severity]
		}

		rawScore := 100 - deduction
		if rawScore < 0 {
			rawScore = 0
		}

		totalWeightedScore += float64(rawScore) * (float64(groupCfg.weight) / 100.0)

		categoryScores[groupName] = models.CategoryScore{
			CategoryName:         groupName,
			Score:                rawScore,
			WeightPercentage:     groupCfg.weight,
			FindingsCount:        len(allGroupFindings),
			ConfirmedIssuesCount: len(groupConfirmed),
		}
	}

	finalScore := int(math.Round(totalWeightedScore))
	if finalScore < 0 {
		finalScore = 0
	} else if finalScore > 100 {
		finalScore = 100
	}

	return &models.ScoreCard{
		OverallScore:            finalScore,
		LetterGrade:             CalculateLetterGrade(finalScore),
		CategoryScores:          categoryScores,
		ConfirmedFlawsCount:     len(confirmed),
		ObservedPropertiesCount: len(observed),
		NotAssessedBoundaries:   DefaultNotAssessedAreas,
	}
}
