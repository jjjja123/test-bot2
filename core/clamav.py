import clamd, asyncio
from .logging import LOGGER

_clam_client = None

async def init_clamav():
    global _clam_client
    try:
        _clam_client = clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310)
        _clam_client.ping()
        LOGGER.info("ClamAV 네트워크 연결 성공")
    except Exception:
        try:
            _clam_client = clamd.ClamdUnixSocket()
            _clam_client.ping()
            LOGGER.info("ClamAV 유닉스 소켓 연결 성공")
        except Exception as e:
            LOGGER.warning(f"ClamAV 연결 실패: {e}")
            _clam_client = None

async def scan_attachment(file_path: str):
    if not _clam_client:
        return False, "ClamAV 비활성"
    try:
        result = _clam_client.scan(file_path)
        if result and file_path in result:
            status, sig = result[file_path]
            if status == "FOUND":
                return True, sig
        return False, "Clean"
    except Exception as e:
        return False, f"ClamAV 오류: {e}"