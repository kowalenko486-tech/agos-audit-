from pydantic import BaseModel, Field, field_validator
from typing import List
from agos.core.provenance import verify_provenance_hash

class Evidence(BaseModel):
    source: str = Field(..., description="Identyfikator zaufanego narzędzia/bazy")
    raw_data: str = Field(..., description="Oryginalny wyciąg z danych, potwierdzający tezę")
    provenance_hash: str = Field(..., description="Kryptograficzny podpis autentyczności (HMAC-SHA256)")

    @field_validator('provenance_hash')
    def validate_signature(cls, v, info):
        if 'source' in info.data and 'raw_data' in info.data:
            if not verify_provenance_hash(info.data['source'], info.data['raw_data'], v):
                raise ValueError("Odmowa systemu: Fałszerstwo dowodu. Niewłaściwy podpis kryptograficzny HMAC.")
        return v

class VerifiedStatement(BaseModel):
    claim: str = Field(..., description="Teza wygenerowana przez agenta")
    evidences: List[Evidence] = Field(..., description="Lista dowodów")

    @field_validator('evidences')
    def ensure_not_empty(cls, v):
        if not v or len(v) == 0:
            raise ValueError("Odmowa systemu: Twierdzenie != Dowód. Brak dołączonego dowodu.")
        return v
