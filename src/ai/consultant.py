import re
from openai import AsyncOpenAI

from src.core.config import settings
from src.ai.schemas import AIConsultantReport
from src.ai.prompts import SYSTEM_PROMPT, build_user_prompt


class SecurityAIConsultant:
    def __init__(self) -> None:
        self.client = AsyncOpenAI(
            base_url=settings.AI_BASE_URL,
            api_key=settings.AI_API_KEY,
        )
        self.model = settings.AI_MODEL

    async def analyze_scan(self, scan_data: dict) -> AIConsultantReport:
        prompt = build_user_prompt(scan_data)

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )

        content = response.choices[0].message.content or "{}"
        
        # Очищаем от возможных Markdown-обёрток ```json ... ```
        clean_json = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.MULTILINE)
        
        return AIConsultantReport.model_validate_json(clean_json)


ai_consultant = SecurityAIConsultant()
