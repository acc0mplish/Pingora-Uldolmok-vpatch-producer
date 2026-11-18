# review-ui — VPATCH 후보 운영자 리뷰 인터페이스

i1745 큐레이션(설계 §7 HITL 계약)의 운영자 리뷰 도구. `candidates/*.json` 후보를
브라우저에서 사람이 직접 판정(승인/기각/보류)하고, 그 결과를 다음 자동화 단계의
입력인 결정 export JSON으로 내보낸다. **이 도구는 판정을 대신하지 않는다** —
승인은 §7 체크리스트 7항 전부 + 익스플로잇 샘플 + source_note가 사람 손으로
입력될 때만 저장된다. 일괄 승인과 source_note 자동 채움은 의도적으로 존재하지
않는다.

## 파일

| 파일 | 성격 |
|---|---|
| `build_data.py` | python3 stdlib 전용 생성기. 외부 의존 없음. 검증 실패 시 exit 1. |
| `review.html` | 자립형 한국어 UI. 유일한 정적 외부 참조는 같은 디렉터의 `data.js`. fetch/XHR·CDN 없음(오프라인 전제). |
| `data.js` | 생성물(커밋 대상 아님 — `.gitignore` 등재). `window.VPATCH_REVIEW_DATA = {...}`. |

## 생성

```bash
python3 tools/review-ui/build_data.py
```

- `candidates/*.json` 전수 파싱 + `candidates/_REVIEW-INDEX.tsv` 대조 검증 +
  후보 복합키(`cve\t<pattern_type>\t<literal>`) 유일성 + provenance kind
  부분집합 `{poc_reference, nvd_cpe}` 검사. 하나라도 어기면 exit 1.
- stdout에 counts(파일/후보/CVE-with-후보/kind 분포)와 힌트별 통계
  (8B 미만·256B 초과·일반단어 단독·대문자/비ASCII·trim 불일치·제어문자·시드
  중복)를 출력한다 — 힌트는 `src/gate/lint.rs`의 literal 검사를 미러한
  **참고용**이며, 최종 판정은 생산자 게이트가 한다.
- 산출 전 자체검증: 합성 입력으로 U+003C 치환이 실제로 동작함을 확인하고
  산출 텍스트에 원문 U+003C 문자가 없음을 보장한다(아래 이스케이프 절).

## 열기

`review.html`을 브라우저에서 file:// 로 열면 된다(서버 불필요):

```
file:///tmp/vpatch-producer/tools/review-ui/review.html
```

`data.js`는 같은 디렉터의 정적 참조물이며, 페이지는 그 외에 어떤 네트워크
호출도 하지 않는다. provenance URL 앵커는 운영자가 직접 클릭할 때만 열리며
http/https만 허용한다(`rel="noopener noreferrer"`).

## 판정 (운영자 §7 체크리스트)

- 각 후보를 펼치면 §7 7체크(설계 문서 §7 원문), 메모, 익스플로잇 샘플,
  source_note, id suffix 입력란이 나온다.
- **승인 저장 조건**: §7 7칸 전부 체크 + 익스플로잇 샘플 비어있지 않음 +
  source_note 비어있지 않음·256바이트 이하. 미충족 시 저장이 차단되고 사유가
  표시된다. source_note(출처·라이선스)는 반드시 사람이 직접 입력한다 — 자동
  채움 경로는 없다.
- **기각 저장 조건**: 메모(사유) 필수.
- 보류는 조건 없음.
- id suffix는 사람이 확정한다. UI는 "이 CVE의 N번째 승인" 서수와
  `vp-cve-<year>-<nnnnn>[-suffix]` 미리보기를 보여줄 뿐, 부여는 운영자가
  확정한다(같은 CVE를 2개 이상 승인할 때 suffix 구분이 필요하다).
- **일괄 승인은 없다.** 일괄 기각/보류만 있고 사유 필수이며, 직전 1단계
  되돌리기(헤더의 되돌리기)를 지원한다.
- CVE 단위 메모는 그룹 메모란에, 후보별 메모는 각 후보의 메모란에 기록된다.

## 저장과 왕복 (export/import가 주 수단)

- localStorage는 **보조 수단**이다(키: `vpatch-review-decisions:<지문 앞 8자>`).
  모든 접근이 try/catch로 감싸져 있고, 헤더에 마지막 쓰기 성공 시각 또는 실패
  원인(QuotaExceededError 포함)이 표시된다. 저장이 불가능한 환경에서 미영속
  판정이 10건을 넘으면 내보내기 권장 배지가 뜬다.
- **내보내기(JSON 다운로드 / JSON 클립보드 복사)**가 주 수단. export는
  자기완결(항목 비정규화 — cve_ids 배열·provenance 전체 포함)이므로 파일만
  리포 밖에 보관하면 /tmp 휘발에도 판정이 살아남는다.
- **가져오기**: 형식(format/version) 확인 후 데이터 지문을 비교한다. 일치하면
  바로 적용하고, 불일치하면 3수치 대화상자 — (1) 현재 데이터에도 존재해 적용될
  판정 key 수(승인/기각/보류 분해) (2) 사라진 판정 key 수 + "사라진 후보의
  판정은 부활하지 않고 폐기됩니다" 명시 (3) 현재 미판정 수 — 확인 후
  **생존 key에만** 적용한다.

## 내구 경로 (/tmp 휘발 대비)

- 이 리포가 `/tmp` 아래에 있으면 재부팅 시 사라진다. 재클론 후 인테이크
  (resume 지원)로 후보를 다시 만들면 **데이터 지문이 달라질 수 있다** — 이전
  export를 가져오기하면 지문 불일치 3수치 대화상자가 뜨고 생존 key만 복원된다.
- export JSON 파일은 리포 **외부**(운영자 워크스페이스)에 보관하는 것을
  권장한다. 판정 데이터의 유일한 내구 사본은 그 파일이다.

## 상수 재동기화

`build_data.py`에 내장된 상수는 출처 주석이 가리키는 원천이 바뀌면 함께
고쳐야 한다:

- `GENERIC_WORDS`(94단어)·바이트 상수(4/8/256)·source_note 256B:
  `src/gate/lint.rs` (L55-150, L34-39)
- 시드 60쌍: 메인 리포 `crates/waf-bundle-encoder/data/seed_patterns.json`
  (codec `seed_blocklist` 자산)

개수 불일치는 생성기가 exit 1로 잡아낸다(94·60 씰). 갱신 후 재생성하면
data.js의 지문은 후보 집합이 같으면 동일하게 유지된다(지문은 상수가 아니라
후보 key 목록의 해시다).

## 이스케이프 근거 (정확한 문구)

data.js는 순 ASCII이며, 문자열 값 안의 U+003C 문자(예: 시드 패턴의
`<script`)는 JSON 문자열 이스케이프(백슬래시 + u003c)로 치환되어 산출된다.
JSON 문법상 U+003C 문자는 문자열 리터럴 내부에만 존재할 수 있으므로, 직렬화된
텍스트 전역 치환은 안전하다(이 근거 문구는 번들 §2.1이 지정한 유일 서술
위치다). `build_data.py`는 이 치환이 실제로 동작하는지 합성 입력으로
자체검증하며, 원문 문자가 산출 바이트에 남지 않음을 재확인한다. 소스상 이
이스케이프 시퀀스는 직접 적지 않고 연접으로 조립한다 — 소스 편집 사고로 문자가
붕괴되는 것을 막기 위함이다(실측 2회 붕괴).

## 수동 검증 절차 (브라우저 자동화 불가 시)

1. `python3 tools/review-ui/build_data.py` — exit 0, counts가
   files=1782 / candidates=1482 / cves_with_candidates=759 /
   poc_reference=1441 / nvd_cpe=41 인지 확인.
2. 브라우저(Chromium 계열)로 review.html을 file:// 로 열기. 개발자 콘솔에
   오류가 없어야 하고, 그룹 수(표시 그룹=759, 전체 후보 1482)와 헤더 통계가
   data.js counts와 일치해야 한다.
3. 왕복: 아무 후보 1건을 §7 7체크+샘플+source_note로 승인, 다른 1건을 사유
   메모로 기각 → 내보내기(JSON 다운로드) → 페이지 새로고침 → 가져오기에서 그
   파일 선택 → 진행률·판정·메모·샘플·source_note·suffix가 전부 일치하는지
   확인.
4. 승인 게이트: 7체크만 채우고 승인 시도 → "저장 차단" 사유 표시 확인.
   source_note를 256바이트 초과로 입력 → 카운터 적색+차단 확인.
5. 지문 불일치: export 파일을 열어 `data_fingerprint`를 임의로 바꿔 저장 →
   가져오기 → 3수치 대화상자 확인 → 취소 시 아무 변화도 없는지 확인.

## export가 다음 자동화의 입력 (candidates 수명주기 계약)

export의 `verdict` 3종이 다음 세션 변환의 입력이다(`schema.rs`·
`gate/corpus.rs`의 수명주기와 일치):

- **승인(approved)** → 후보 status를 `proposed`→`approved`로 전환하고
  `rules/<id>.json`을 추가하는 curation PR. 승인분의 린트는 rules/ 쪽 게이트가
  담당한다. 최종 rule id는 export의 `cve_ids`·`id_suffix`·서수(그 CVE 내
  승인 순서)로 도출된다.
- **기각(rejected)** → curation PR에서 해당 candidates 엔트리 제거. 메모(사유)가
  기록 돼 있다.
- **보류(deferred)** → `proposed` 그대로 유지(다음 사이클 재검토).

`validation.invalid_approved_keys`에는 현재 승인 게이트(§7 7체크+샘플+
source_note 256B)를 통과하지 못하는 승인이 기록된다 — 이 목록이 비어 있어야
다음 자동화에 넘길 수 있다.
