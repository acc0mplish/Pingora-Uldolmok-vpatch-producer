# uldolmok-vpatch-producer

UVPB(Uldolmok Virtual-Patch Bundle) v1 생산자 소스 리포 — 큐레이션·서명·발행 파이프라인.

- 규범 설계: `Pingora-Uldolmok` 리포 `docs/task-id/i1745-bundle-producer/design.md` (r3.2 FINAL)
- 형식 스펙 원천: `Pingora-Uldolmok` 리포 `docs/security/virtual-patch-bundle-format.md`
- 코덱: `Pingora-Uldolmok` 리포 `crates/waf-bundle-encoder` (git 핀 — `pin.rev`가 기대 rev 소유)
- ****테스트 단계 public** (실전 전환 P-P3 전 private 복귀 권장 — 큐레이션 은닉)** — 서명 키 시드·큐레이션 이력 포함. 공개 아티팩트는 dist 리포(`vpatch-dist`)로만 게시된다.

## 구조 (설계 §9 P-P0~P-P4)

- `rules/` — 승인된 룰 (CODEOWNERS 보호)
- `candidates/` — 자동 후보 (CODEOWNERS 보호)
- `corpus/` — benign 코퍼스 (CODEOWNERS 보호)
- `state.json` — sequence·current_key_id 소유자 (서명 잡만 갱신)
- `pin.rev` — 코덱 기대 rev (CODEOWNERS 보호·스케줄드 핀 갱신 잡이 유일 기록자)
- `.github/workflows/` — 서명(2-잡 분리)·드리프트 게이트·케이던스 감시 (D3·D5·M3)

## 운영자 설정 체크리스트 (P-P0 잔여 — 코드로 불가)

1. 읽기 PAT(contents:read)를 secret `ULDOLMOK_REPO_PAT`으로 등록
2. Ed25519 키 시드 32B를 secret `UVPB_SIGN_SEED`로 등록 (오프라인 원본 보관: 암호화 파일+오프사이트)
3. environment `signing` 생성·승인자 지정 (2인 규칙)
4. ~~기본 브랜치 보호~~ 테스트 단계 생략(운영자 2026-11-17)
5. 큐레이터 1인 추가 지정 (CODEOWNERS 갱신)
