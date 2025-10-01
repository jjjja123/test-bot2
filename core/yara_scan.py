import os
from .logging import LOGGER

try:
    import yara
except Exception:
    yara = None

_yara_rules = None

def load_yara_rules(rule_dir: str = "./yara_rules"):
    """지정된 디렉토리에서 YARA 룰 파일들을 로드"""
    global _yara_rules
    if not yara:
        LOGGER.warning("YARA 라이브러리 없음. 룰 검사 비활성화됨.")
        return None
    if not os.path.isdir(rule_dir):
        LOGGER.warning(f"YARA 룰 디렉토리 없음: {rule_dir}")
        return None

    rule_files = {}
    for fname in os.listdir(rule_dir):
        if fname.endswith(".yar") or fname.endswith(".yara"):
            rule_files[fname] = os.path.join(rule_dir, fname)

    if not rule_files:
        LOGGER.warning("YARA 룰 파일 없음.")
        return None

    try:
        _yara_rules = yara.compile(filepaths=rule_files)
        LOGGER.info(f"YARA 룰 {len(rule_files)}개 로드 완료")
    except Exception as e:
        LOGGER.exception(f"YARA 룰 컴파일 실패: {e}")
        _yara_rules = None

async def yara_scan(file_path: str):
    """단일 파일에 대해 YARA 룰 검사 수행"""
    if not _yara_rules:
        return False, "No YARA rules"
    try:
        matches = _yara_rules.match(file_path)
        if matches:
            return True, f"YARA 매치: {[m.rule for m in matches]}"
        return False, "YARA 통과"
    except Exception as e:
        LOGGER.exception(f"YARA 검사 실패: {e}")
        return False, "YARA 오류"