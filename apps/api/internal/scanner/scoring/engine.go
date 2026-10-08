package scoring

import (
	"math"

	"github.com/expose/expose/apps/api/internal/domain"
)

const ScoreVersion = "1.0"

var canonicalCategories = []struct {
	Category domain.Category
	Weight   int
}{
	{domain.CategoryTransportSecurity, 15},
	{domain.CategoryBrowserSecurity, 15},
	{domain.CategoryCookieSessionSecurity, 10},
	{domain.CategoryConfiguration, 10},
	{domain.CategoryAttackSurface, 10},
	{domain.CategoryInformationExposure, 10},
	{domain.CategoryAPISecurity, 10},
	{domain.CategoryThirdPartyResources, 10},
	{domain.CategoryAuthentication, 10},
}

var severityPenalties = map[domain.Severity]int{
	domain.SeverityCritical: 35,
	domain.SeverityHigh:     20,
	domain.SeverityMedium:   10,
	domain.SeverityLow:      3,
	domain.SeverityInfo:     0,
}

var nonAssessedAreas = []domain.NotAssessedArea{
	{
		Area:        "Authentication & Credential Evaluation",
		Reason:      "Prohibited Without Tenant Authorization",
		Explanation: "Login brute-forcing, password fuzzing, and authenticated privilege escalation testing are strictly out of scope.",
	},
	{
		Area:        "Active Code Injection (SQLi, RCE, Command Injection)",
		Reason:      "Non-Destructive Scanning Policy",
		Explanation: "Expose never fires exploitative fuzzing payloads that could corrupt backend databases or destabilize target services.",
	},
	{
		Area:        "Business Logic & State Workflows",
		Reason:      "Requires Multi-Step Internal Context",
		Explanation: "Checkout cart manipulation, race conditions, and application workflow integrity cannot be assessed from external observation.",
	},
	{
		Area:        "Internal Cloud Topologies & VPC Networks",
		Reason:      "Externally Inaccessible",
		Explanation: "Internal VPC IP spaces, database backends, and container orchestrators behind reverse proxies are not reachable from the Internet.",
	},
	{
		Area:        "Proprietary Source Code & CI/CD Pipelines",
		Reason:      "Static Analysis Boundary",
		Explanation: "Client-side bundles are inspected, but internal source repositories and deployment pipelines are not accessed.",
	},
}

func mapToCanonicalCategory(c domain.Category) domain.Category {
	switch c {
	case domain.CategoryTransportSecurity, domain.CategoryCryptography:
		return domain.CategoryTransportSecurity
	case domain.CategoryBrowserSecurity, domain.CategoryHTTPHeaders, domain.CategoryMixedContent:
		return domain.CategoryBrowserSecurity
	case domain.CategoryCookieSessionSecurity, domain.CategoryCookieSecurity:
		return domain.CategoryCookieSessionSecurity
	case domain.CategoryConfiguration, domain.CategorySecurityMetadata, domain.CategoryNetworkPosture:
		return domain.CategoryConfiguration
	case domain.CategoryAttackSurface, domain.CategoryClientSideSecurity:
		return domain.CategoryAttackSurface
	case domain.CategoryInformationExposure, domain.CategoryInformationDisclosure:
		return domain.CategoryInformationExposure
	case domain.CategoryAPISecurity:
		return domain.CategoryAPISecurity
	case domain.CategoryThirdPartyResources, domain.CategoryExternalExposure:
		return domain.CategoryThirdPartyResources
	case domain.CategoryAuthentication:
		return domain.CategoryAuthentication
	default:
		return domain.CategoryConfiguration
	}
}

// CalculateScoreCard evaluates findings and produces a deterministic 0-100 ScoreCard (Phase 9 v1.0).
// Adheres strictly to: "Do not use severity as a substitute for confidence. A theoretical weakness should not be presented as a confirmed vulnerability."
func CalculateScoreCard(findings []domain.Finding) *domain.ScoreCard {
	// Initialize category metrics
	categoryScores := make(map[string]domain.CategoryScore)
	categoryDeductions := make(map[domain.Category]int)
	categoryTotalFindings := make(map[domain.Category]int)
	categoryConfirmedIssues := make(map[domain.Category]int)

	confirmedFlawsCount := 0
	observedPropertiesCount := 0

	for _, f := range findings {
		canonicalCat := mapToCanonicalCategory(f.Category)
		categoryTotalFindings[canonicalCat]++

		// Determine confidence multiplier: empirical proof carries full weight; theoretical/potential weaknesses do not
		confidenceFactor := 1.0
		switch f.Confidence {
		case domain.ConfidenceConfirmed:
			confidenceFactor = 1.0
		case domain.ConfidenceLikely:
			confidenceFactor = 0.75
		case domain.ConfidencePotential:
			confidenceFactor = 0.35
		case domain.ConfidenceInformational:
			confidenceFactor = 0.0
		default:
			confidenceFactor = 0.5
		}

		if f.Confidence == domain.ConfidenceConfirmed && f.Status == domain.StatusConfirmed {
			if f.Severity != domain.SeverityInfo {
				confirmedFlawsCount++
				categoryConfirmedIssues[canonicalCat]++
			} else {
				observedPropertiesCount++
			}
		} else {
			observedPropertiesCount++
		}

		if f.Severity != domain.SeverityInfo && confidenceFactor > 0 {
			basePenalty := float64(severityPenalties[f.Severity])
			weightedPenalty := int(math.Round(basePenalty * confidenceFactor))
			if weightedPenalty < 1 && basePenalty > 0 {
				weightedPenalty = 1
			}
			categoryDeductions[canonicalCat] += weightedPenalty
		}
	}

	totalWeightedScore := 0.0
	totalWeightSum := 0

	for _, entry := range canonicalCategories {
		cat := entry.Category
		weight := entry.Weight
		deduction := categoryDeductions[cat]
		score := 100 - deduction
		if score < 0 {
			score = 0
		}

		categoryScores[string(cat)] = domain.CategoryScore{
			CategoryName:         string(cat),
			Score:                score,
			WeightPercentage:     weight,
			FindingsCount:        categoryTotalFindings[cat],
			ConfirmedIssuesCount: categoryConfirmedIssues[cat],
		}

		totalWeightedScore += float64(score * weight)
		totalWeightSum += weight
	}

	finalScore := 100
	if totalWeightSum > 0 {
		finalScore = int(math.Round(totalWeightedScore / float64(totalWeightSum)))
	}
	if finalScore < 0 {
		finalScore = 0
	} else if finalScore > 100 {
		finalScore = 100
	}

	letterGrade := "F"
	switch {
	case finalScore >= 90:
		letterGrade = "A"
	case finalScore >= 80:
		letterGrade = "B"
	case finalScore >= 70:
		letterGrade = "C"
	case finalScore >= 60:
		letterGrade = "D"
	default:
		letterGrade = "F"
	}

	return &domain.ScoreCard{
		ScoreVersion:            ScoreVersion,
		OverallScore:            finalScore,
		LetterGrade:             letterGrade,
		CategoryScores:          categoryScores,
		ConfirmedFlawsCount:     confirmedFlawsCount,
		ObservedPropertiesCount: observedPropertiesCount,
		NotAssessedBoundaries:   nonAssessedAreas,
	}
}
