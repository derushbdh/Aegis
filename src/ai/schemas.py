from pydantic import BaseModel, Field

class AIConsultantReport(BaseModel):
    verdict: str = Field(
        description="Brief expert verdict from a white-hat security auditor regarding the website's security posture"
    )
    risks: list[str] = Field(
        description="List of identified security risks and potential attack scenarios in plain English"
    )
    recommendations: list[str] = Field(
        description="Concrete, actionable recommendations for remediating vulnerabilities"
    )