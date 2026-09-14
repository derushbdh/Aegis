from pydantic import BaseModel, Field

class AIConsultantReport(BaseModel):
    verdict: str = Field(
        description="Краткий экспертный вердикт белого хакера о текущем состоянии сайта"
    )
    risks: list[str] = Field(
        description="Список выявленных рисков и возможных сценариев атак простым языком"
    )
    recommendations: list[str] = Field(
        description="Конкретные пошаговые рекомендации для исправления уязвимостей"
    )