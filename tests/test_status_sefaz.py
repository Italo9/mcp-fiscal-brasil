"""Testes para status_sefaz.py (consulta real NfeStatusServico4 - mocks, sem SEFAZ real)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from lxml import etree

from mcp_fiscal_brasil._core.errors import FiscalConfigurationError, FiscalHTTPError
from mcp_fiscal_brasil.nfe.status_sefaz import (
    StatusSefazReal,
    _endpoint_para_uf,
    consultar_status_real,
    obter_status_certificado,
)

_NS_NFE = "http://www.portalfiscal.inf.br/nfe"


@pytest.fixture(scope="module")
def chave_privada_a1() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def certificado_a1(chave_privada_a1: rsa.RSAPrivateKey) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.COMMON_NAME, "EMPRESA TESTE:12345678000195"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(chave_privada_a1.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(chave_privada_a1, hashes.SHA256())
    )


@pytest.fixture(scope="module")
def arquivo_pfx(
    chave_privada_a1: rsa.RSAPrivateKey,
    certificado_a1: x509.Certificate,
    tmp_path_factory: pytest.TempPathFactory,
) -> str:
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        b"cert_teste",
        chave_privada_a1,
        certificado_a1,
        None,
        serialization.BestAvailableEncryption(b"senha_teste"),
    )
    tmp_dir = tmp_path_factory.mktemp("certs_status")
    pfx_path = str(tmp_dir / "cert_teste.pfx")
    with open(pfx_path, "wb") as f:
        f.write(pfx_bytes)
    return pfx_path


def _montar_ret_stat_serv(c_stat: str, x_motivo: str = "Servico em Operacao") -> etree._Element:
    body_str = (
        f'<retConsStatServ versao="4.00" xmlns="{_NS_NFE}">'
        "<tpAmb>1</tpAmb>"
        "<verAplic>SP_20200205</verAplic>"
        f"<cStat>{c_stat}</cStat>"
        f"<xMotivo>{x_motivo}</xMotivo>"
        "<cUF>35</cUF>"
        "<dhRecbto>2026-07-18T10:00:00-03:00</dhRecbto>"
        "<tMed>1</tMed>"
        "</retConsStatServ>"
    )
    return etree.fromstring(body_str.encode())


class TestEndpointParaUf:
    def test_uf_com_estrutura_propria(self) -> None:
        assert "sp" in _endpoint_para_uf("SP", "producao").lower()

    def test_uf_svrs(self) -> None:
        assert "svrs" in _endpoint_para_uf("RJ", "producao").lower()

    def test_uf_svan(self) -> None:
        assert "sefazvirtual" in _endpoint_para_uf("MA", "producao").lower()

    def test_homologacao_usa_url_diferente(self) -> None:
        assert _endpoint_para_uf("SP", "producao") != _endpoint_para_uf("SP", "homologacao")


class TestConsultarStatusReal:
    async def test_sem_certificado_levanta_configuration_error(self) -> None:
        with pytest.raises(FiscalConfigurationError):
            await consultar_status_real("SP", caminho_certificado="", senha="")

    async def test_cstat_107_retorna_operacional(self, arquivo_pfx: str) -> None:
        body_mock = _montar_ret_stat_serv("107")
        with patch(
            "mcp_fiscal_brasil.nfe.status_sefaz._enviar_soap_mtls",
            new=AsyncMock(return_value=body_mock),
        ), patch("mcp_fiscal_brasil.nfe.status_sefaz._ssl_context_cache", None):
            resultado = await consultar_status_real(
                "SP", caminho_certificado=arquivo_pfx, senha="senha_teste"
            )

        assert isinstance(resultado, StatusSefazReal)
        assert resultado.status == "OPERACIONAL"
        assert resultado.codigo == 107

    async def test_cstat_108_retorna_instavel(self, arquivo_pfx: str) -> None:
        body_mock = _montar_ret_stat_serv("108", "Servico Paralisado Momentaneamente")
        with patch(
            "mcp_fiscal_brasil.nfe.status_sefaz._enviar_soap_mtls",
            new=AsyncMock(return_value=body_mock),
        ), patch("mcp_fiscal_brasil.nfe.status_sefaz._ssl_context_cache", None):
            resultado = await consultar_status_real(
                "SP", caminho_certificado=arquivo_pfx, senha="senha_teste"
            )

        assert resultado.status == "INSTAVEL"

    async def test_cstat_109_retorna_indisponivel(self, arquivo_pfx: str) -> None:
        body_mock = _montar_ret_stat_serv("109", "Servico Paralisado sem Previsao")
        with patch(
            "mcp_fiscal_brasil.nfe.status_sefaz._enviar_soap_mtls",
            new=AsyncMock(return_value=body_mock),
        ), patch("mcp_fiscal_brasil.nfe.status_sefaz._ssl_context_cache", None):
            resultado = await consultar_status_real(
                "SP", caminho_certificado=arquivo_pfx, senha="senha_teste"
            )

        assert resultado.status == "INDISPONIVEL"

    async def test_cstat_inesperado_levanta_http_error(self, arquivo_pfx: str) -> None:
        body_mock = _montar_ret_stat_serv("215", "Rejeicao: Falha no schema XML")
        with patch(
            "mcp_fiscal_brasil.nfe.status_sefaz._enviar_soap_mtls",
            new=AsyncMock(return_value=body_mock),
        ), patch("mcp_fiscal_brasil.nfe.status_sefaz._ssl_context_cache", None), pytest.raises(
            FiscalHTTPError
        ):
            await consultar_status_real("SP", caminho_certificado=arquivo_pfx, senha="senha_teste")

    async def test_senha_incorreta_propaga_erro(self, arquivo_pfx: str) -> None:
        with patch("mcp_fiscal_brasil.nfe.status_sefaz._ssl_context_cache", None):
            with pytest.raises(Exception):
                await consultar_status_real(
                    "SP", caminho_certificado=arquivo_pfx, senha="senha_errada"
                )


class TestObterStatusCertificado:
    def test_sem_certificado_configurado(self) -> None:
        resultado = obter_status_certificado(caminho_certificado="", senha="", ambiente="producao")
        assert resultado.configurado is False
        assert resultado.cnpj is None

    def test_certificado_valido(self, arquivo_pfx: str) -> None:
        resultado = obter_status_certificado(
            caminho_certificado=arquivo_pfx, senha="senha_teste", ambiente="producao"
        )
        assert resultado.configurado is True
        assert resultado.cnpj == "12345678000195"
        assert resultado.valido is True
        assert resultado.validade_fim is not None

    def test_senha_incorreta_retorna_erro_sem_expor_detalhes_sensiveis(
        self, arquivo_pfx: str
    ) -> None:
        resultado = obter_status_certificado(
            caminho_certificado=arquivo_pfx, senha="senha_errada", ambiente="producao"
        )
        assert resultado.configurado is True
        assert resultado.erro is not None
