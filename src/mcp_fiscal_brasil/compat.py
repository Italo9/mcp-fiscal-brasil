"""Camada de compatibilidade para o contrato REST do Lumiere.

O Lumiere (loja_virtual_irma) espera respostas camelCase com campos
especificos. Este modulo converte os schemas Pydantic do mcp-fiscal-brasil
para esse contrato, mantendo a API publica original intacta.
"""

from __future__ import annotations

from typing import Any

from .cnpj.schemas import CNPJResponse
from .simples.schemas import SimplesStatus
from .agentic.schemas import ComplianceReport, SupplierRiskScore
from .nfe.schemas import NFeResponse, StatusSEFAZResponse

_RECOMENDACAO_TO_STATUS = {
    "aprovar": "APROVAR",
    "aprovar_com_ressalvas": "APROVAR",
    "investigar": "INVESTIGAR",
    "recusar": "RECUSAR",
}

_RISCO_TO_STATUS = {
    "baixo": "APROVAR",
    "medio": "INVESTIGAR",
    "alto": "INVESTIGAR",
    "critico": "RECUSAR",
}


def cnpj_to_lumiere(data: dict[str, Any]) -> dict[str, Any]:
    """Converte resposta de CNPJ para o contrato do Lumiere."""
    endereco = data.get("endereco") or {}
    atividade = data.get("atividade_principal") or {}
    return {
        "cnpj": data.get("cnpj", ""),
        "razaoSocial": data.get("razao_social", ""),
        "nomeFantasia": data.get("nome_fantasia"),
        "situacao": (data.get("situacao_cadastral") or "DESCONHECIDA").upper(),
        "dataAbertura": str(data["data_abertura"]) if data.get("data_abertura") else None,
        "cnaePrincipal": {
            "codigo": atividade.get("código", ""),
            "descricao": atividade.get("descrição", ""),
        } if atividade else None,
        "uf": endereco.get("uf"),
        "municipio": endereco.get("municipio"),
    }


def simples_to_lumiere(data: dict[str, Any]) -> dict[str, Any]:
    """Converte resposta de Simples Nacional para o contrato do Lumiere."""
    return {
        "optante": data.get("simples_nacional", False),
        "dataOpcao": str(data["data_opcao"]) if data.get("data_opcao") else None,
        "dataExclusao": str(data["data_exclusao"]) if data.get("data_exclusao") else None,
        "simei": data.get("mei", False),
    }


def supplier_to_lumiere(data: dict[str, Any]) -> dict[str, Any]:
    """Converte SupplierRiskScore para o contrato do Lumiere."""
    rec = data.get("recomendacao", "")
    status = _RECOMENDACAO_TO_STATUS.get(rec, "PENDENTE")
    fatores_list = data.get("fatores") or []
    fatores_obj: dict[str, Any] = {}
    for i, f in enumerate(fatores_list):
        fatores_obj[f"fator_{i+1}"] = f
    return {
        "cnpj": data.get("cnpj", ""),
        "score": data.get("score", 0),
        "status": status,
        "fatores": fatores_obj,
        "recomendacao": data.get("recomendacao"),
    }


def compliance_to_lumiere(data: dict[str, Any]) -> dict[str, Any]:
    """Converte ComplianceReport para o contrato do Lumiere."""
    achados = data.get("achados") or []
    alertas = [a.get("titulo", "") for a in achados if a.get("severidade") in ("alto", "critico")]
    return {
        "cnpj": data.get("cnpj", ""),
        "score": data.get("score", 0),
        "situacao": (data.get("risco_geral") or "DESCONHECIDA").upper(),
        "alertas": alertas,
        "resumo": data.get("resumo_executivo"),
    }


def nfe_to_lumiere(data: dict[str, Any]) -> dict[str, Any]:
    """Converte NFeResponse para o contrato do Lumiere."""
    itens_raw = data.get("itens") or []
    itens = [
        {
            "descricao": item.get("descrição", ""),
            "quantidade": item.get("quantidade", 0),
            "valor": item.get("valor_total", 0),
        }
        for item in itens_raw
    ]
    emitente = data.get("emitente") or {}
    destinatario = data.get("destinatario") or {}
    totais = data.get("totais") or {}
    return {
        "chave": data.get("chave_acesso", ""),
        "valida": True,
        "emitente": emitente.get("nome"),
        "destinatario": destinatario.get("nome"),
        "valorTotal": totais.get("valor_nota"),
        "dataEmissao": str(data["data_emissao"]) if data.get("data_emissao") else None,
        "itens": itens,
    }


def nfe_chave_to_lumiere(chave: str, validacao: dict[str, Any]) -> dict[str, Any]:
    """Converte validacao de chave NFe para o contrato do Lumiere."""
    return {
        "chave": chave,
        "valida": validacao.get("válido", False),
        "emitente": None,
        "destinatario": None,
        "valorTotal": None,
        "dataEmissao": None,
        "itens": [],
    }


def sefaz_status_to_lumiere(status_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Converte lista de StatusSEFAZResponse para o contrato do Lumiere."""
    ufs = []
    for s in status_list:
        st = (s.get("status") or "").upper()
        if "OPERACIONAL" in st or "OPERACAO" in st:
            normalized = "OPERACIONAL"
        elif "INSTAVEL" in st or "INSTAB" in st:
            normalized = "INSTAVEL"
        else:
            normalized = "INDISPONIVEL"
        ufs.append({"uf": s.get("uf", ""), "status": normalized})
    return {"ufs": ufs}
