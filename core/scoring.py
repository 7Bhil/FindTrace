from core.config import THREAT_PATTERNS, REGION_WEIGHTS, MAX_SCORE

class GlobalScoringEngine:
    """
    FindTrace 2.0 Global Scoring Engine.
    Scales results up to 1000 points with regional weighting.
    """
    @staticmethod
    def calculate_risk(findings_summary: str) -> tuple[int, list[str]]:
        total_score = 0
        observations = []
        
        # Calculate regional contributions
        regional_scores = {region: 0 for region in REGION_WEIGHTS.keys()}
        
        for pattern, data in THREAT_PATTERNS.items():
            if pattern.lower() in findings_summary.lower():
                risk = data["risk"]
                region = data["region"]
                desc = data["desc"]
                
                # Apply regional contribution
                regional_scores[region] += risk
                observations.append(desc)
        
        # Merge scores using regional weights
        for region, score in regional_scores.items():
            weight = REGION_WEIGHTS.get(region, 1.0)
            total_score += (score * weight)
            
        return min(int(total_score), MAX_SCORE), list(set(observations))
