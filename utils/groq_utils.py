import os
from datetime import datetime
import groq

class GroqManager:
    """Handles Groq AI draft generation strictly from provided input."""

    def __init__(self):
        # Store API key safely
        self.api_key = os.getenv("GROQ_API_KEY", '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')
        self.client = groq.Groq(api_key=self.api_key)
        self.model_name = "llama-3.3-70b-versatile"

    # ----------------------------------------------------------------------
    #  MAIN AI DRAFT GENERATOR
    # ----------------------------------------------------------------------
    def generate_draft(self, case_details, medical_summary, retrieved_templates):
        """
        Generate a professional legal demand draft using only user-provided inputs.
        Templates are referenced solely for tone/structure.
        """
        prompt = self._build_prompt(case_details, medical_summary, retrieved_templates)
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                temperature=0.6,
                top_p=0.95,
                max_tokens=4000,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a professional legal AI assistant that drafts "
                            "high-quality demand letters. "
                            "STRICT RULE: Do not add any information beyond what the user provides. "
                            "Do not fetch external facts. Use templates only for tone and formatting."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error generating draft: {e}"

    # ----------------------------------------------------------------------
    #  SMART PROMPT BUILDER
    # ----------------------------------------------------------------------
    def _build_prompt(self, case_details, medical_summary, retrieved_templates):
        """Construct a strict prompt for AI to generate a factually accurate draft."""
        current_date = datetime.now().strftime("%B %d, %Y")

        plaintiff = case_details.get("plaintiff", "Client")
        defendant = case_details.get("defendant", "Defendant")
        case_type = case_details.get("case_type", "Personal Injury")
        jurisdiction = case_details.get("jurisdiction", "California")
        injury_type = case_details.get("injury_type", "Various injuries")
        treatment_cost = case_details.get("treatment_cost", 0)
        attorney_name = case_details.get("attorney_name", "Legal Counsel")
        law_firm_name = case_details.get("law_firm_name", "Law Office")
        additional_details = case_details.get("additional_details", "")

        template_text = "\n\n--- TEMPLATE REFERENCE ---\n\n".join(retrieved_templates[:3]) if retrieved_templates else "No templates available."

        return f"""
You are a highly specialized legal AI. Generate a **full, professional demand letter** strictly based on the following inputs. 

### ⚠️ STRICT RULES
- ONLY use information provided in the inputs below. Do not invent names, dates, addresses, or details.
- Templates may be used **only for tone and formatting**, not content.
- Ensure the letter is complete, structured, and professional.
- Include a table for damages if applicable.
- Maintain neutral, factual, and persuasive tone.
- Use professional legal formatting: bold section headings, proper tables, clear paragraphs.
- Do NOT use Markdown headings (#, ##, ###).
- Write fully professional, persuasive, and factual demand letter.
- Only use the facts provided; templates are reference for tone/structure only.
- Do not add any external information or assumptions.
- Ensure the letter is self-contained and does not reference external documents.
- Use short paragraphs (4-5 lines each) for readability.
- Don't mention introduction, conclusion, or any other sections explicitly.
- Ensure all tables are cleanly formatted with category and amount columns.
- The letter should be ready to send with no further edits needed.
- If any required information is missing in the template retrieval, **ignore the missing parameters** and generate the draft **fully complete** based on the facts provided.
- Do not use placeholders for missing template parameters; generate the draft naturally with the available data.
- If any parameter (like lost wages or total damages) is missing in the inputs, do NOT write placeholders like "To be determined". 
- Only include rows in the damages table for which values are provided. 
- The draft should still be complete and professional even if some rows are missing.
- If treatment cost is not provided, omit the treatment cost row from the damages table.
- Act as a senior legal editor ensuring clarity, tone, and professionalism.
- Do not add any new facts or assumptions in the rewrite.
- The final output should be a polished, professional demand letter ready for client review.
- if Lost Wages or any other damages are not provided, consider treatment cost as total damages.

### CASE INFORMATION
- Date: {current_date}
- Plaintiff: {plaintiff}
- Defendant: {defendant}
- Jurisdiction: {jurisdiction}
- Case Type: {case_type}
- Injury Type: {injury_type}
- Treatment Cost: ${treatment_cost:,}
- Additional Details: {additional_details}
- Attorney: {attorney_name}
- Law Firm: {law_firm_name}

### MEDICAL SUMMARY
{medical_summary.strip()}

### TEMPLATE STYLE REFERENCE
{template_text}

### OUTPUT REQUIREMENTS
- Bold heading: 'Demand Letter – {case_type} Case'
- Address block: To {defendant}, Jurisdiction: {jurisdiction}
- RE line: {case_type} Claim – {plaintiff} vs. {defendant}
- Sections: Introduction, Statement of Facts, Injuries & Treatment, Damages, Compensation Table, Conclusion
- Signature block with attorney and law firm
- Tables formatted cleanly with category and amount
- Use short paragraphs (3–4 lines each)
- No external facts or assumptions
- Fully self-contained letter
"""

    # ----------------------------------------------------------------------
    #  REWRITE DRAFT / IMPROVEMENT ENGINE
    # ----------------------------------------------------------------------
    def rewrite_draft(self, original_draft, improvement_goal):
        """
        Rewrite and improve the draft while strictly keeping facts intact.
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                temperature=0.5,
                top_p=0.9,
                max_tokens=3500,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior legal editor. Rewrite the provided legal draft to improve it based on the user's goal. "
                            "STRICT RULES:\n"
                            "1. Keep ALL factual information exactly the same\n"
                            "2. Do not add any new facts, numbers, or claims\n"
                            "3. Do not change the meaning or legal arguments\n"
                            "4. Only improve: clarity, tone, professionalism, persuasiveness\n"
                            "5. Maintain the same structure and sections\n"
                            "6. Keep all tables and financial amounts identical\n"
                            "7. Return a complete, polished draft ready for use\n"
                            "8. If you cannot improve it due to constraints, return the original draft unchanged"
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"IMPROVEMENT GOAL: {improvement_goal}\n\n"
                                  f"ORIGINAL DRAFT:\n{original_draft}\n\n"
                                  f"IMPROVED DRAFT:"
                    },
                ],
            )
            result = response.choices[0].message.content.strip()
            
            # Validate that the response is not an error message
            if not result or "error" in result.lower() or "sorry" in result.lower():
                return original_draft  # Return original if AI response is problematic
                
            return result
            
        except Exception as e:
            # Instead of returning an error string, return the original draft
            print(f"AI Rewrite error: {e}")  # For debugging
            return original_draft  # Fallback to original draft