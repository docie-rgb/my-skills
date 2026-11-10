---
name: public-repo-audit
description: 개인 개발 프로젝트를 GitHub 공개 저장소로 올리기 전(또는 이미 공개한 저장소를 다시 확인할 때) 보안·개인정보 노출·문서 누락을 읽기 전용으로 점검하고 중요도별 보고서를 출력한다. 사용자가 "공개 저장소 점검해 줘", "GitHub 올리기 전에 확인해 줘", "푸시 전에 비밀키 새는지 봐 줘", "개인정보 노출 여부 점검해 줘", ".env 커밋됐는지 확인해 줘", "public으로 바꿔도 되는지 봐 줘", "pre-publish check", "audit this repo before making it public"처럼 요청하면 이 스킬을 사용한다. 코드 리뷰나 기능 버그 점검 요청에는 사용하지 않는다.
---

# public-repo-audit — GitHub 공개 전 점검

개인 프로젝트를 GitHub에 공개하기 직전에 매번 손으로 하던 확인 작업을 같은 순서로 수행하고, 결과를 하나의 보고서로 정리한다.

## 반드시 지킬 규칙

1. **읽기 전용.** 파일 수정·삭제, `git add/commit/push`, `git rm --cached`, 이력 재작성(`filter-repo`, `rebase`, BFG 등), 원격 저장소 공개 설정 변경은 **사용자의 명시적 승인 없이 하지 않는다.** 조치는 보고서에 "권장 조치"로만 적는다.
2. **비밀 값은 절대 출력하지 않는다.** 보고서·대화·명령 출력 어디에도 실제 키·토큰·비밀번호·개인정보 값을 쓰지 않는다. `파일:줄번호`, 변수 이름, 패턴 종류, 마스킹 값(앞 4자 + `****`)만 쓴다. 검색 명령은 값이 화면에 나오지 않도록 `-l`(파일명만), `-c`(개수만) 또는 마스킹 파이프를 쓴다.
3. **완전성을 주장하지 않는다.** 보고서에 검사 범위와 한계를 반드시 적고, "비밀정보 없음"이 아니라 "이번 패턴 검사에서는 발견되지 않음"이라고 쓴다.
4. 대상은 사용자가 지정한 폴더, 지정이 없으면 현재 작업 디렉터리의 Git 루트다.

## 점검 절차

각 단계의 결과를 기록해 두었다가 7단계 보고서에 모은다. 명령은 Git Bash 기준이며, 다른 셸이면 같은 의미의 명령으로 바꾼다.

### 1. Git 저장소 상태와 추적 파일 확인

```bash
git rev-parse --show-toplevel
git status --short --branch
git remote -v
git log --oneline -n 10
git ls-files | wc -l
git ls-files
```

- 원격이 있으면 이미 공개됐는지(사용자에게 확인하거나 `gh repo view --json visibility`가 가능하면 사용) 기록한다. 이미 공개된 저장소라면 "이력에 남은 비밀은 이미 노출된 것으로 간주"해야 함을 보고서에 적는다.
- 추적 파일 목록에서 아래 항목을 찾는다: `.env*`(단 `.env.example`/`.env.sample` 제외), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `*.sqlite`, `*.db`, `*.dump`, `*.sql` 데이터 덤프, `credentials*.json`, `service-account*.json`, `*.log`, `node_modules/`, `.venv/`, 대용량 바이너리.

### 2. 비밀정보·개인식별정보 노출 가능성 검사

**현재 추적 파일**(작업 트리가 아닌 Git이 올릴 파일)을 대상으로 검색한다. 값이 출력되지 않도록 파일명과 개수만 본다.

```bash
# 키/토큰 형태 (파일명만)
git grep -lE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.'

# 이름=값 형태의 하드코딩 (줄번호 + 변수명만, 값은 마스킹)
git grep -nIiE '(password|passwd|secret|token|api[_-]?key|service[_-]?role|private[_-]?key|client[_-]?secret|database_url)\s*[:=]\s*["'"'"']?[^"'"'"' ]{6,}' \
  | sed -E 's/((password|passwd|secret|token|api[_-]?key|service[_-]?role|private[_-]?key|client[_-]?secret|database_url)[[:space:]]*[:=][[:space:]]*["'"'"']?)(.{0,4})[^"'"'"' ,)]*/\1\3****/Ig' \
  | cut -c1-160
# 대부분은 `token = request.cookies.get(...)` 같은 변수 대입(오탐)이다. 문자열 리터럴이 대입된 줄만 실제 후보로 본다.

# 연결 문자열 안의 비밀번호 (파일명만)
git grep -lE '[a-z]+://[^/:@ ]+:[^@/ ]+@'

# 개인식별정보 후보 (개수만 → 필요 시 파일:줄번호만 확인)
git grep -cE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'      # 이메일
git grep -cE '01[016789]-?[0-9]{3,4}-?[0-9]{4}'                       # 휴대전화
git grep -cE '[0-9]{6}-[1-4][0-9]{6}'                                 # 주민등록번호 형태
```

판정 요령:
- 플레이스홀더(`your-key-here`, `xxx`, `changeme`, `example.com`, 테스트용 더미)는 **오탐**으로 분류하되 보고서에 근거를 적는다.
- Supabase/Firebase의 `anon`/공개 키처럼 클라이언트 공개용 키는 "공개 전제 키"로 분류하되, `service_role`/관리자 키는 즉시 위험이다.
- 이메일·전화번호가 시연 데이터인지 실제 개인 정보인지 판단이 어려우면 "확인 필요"로 두고 사용자에게 묻는다.
- 문서(README, PRD, docs/)에 **실명, 실제 회사명, 내부 URL, 비공개 프로젝트명, 로컬 사용자 경로(`C:\Users\<이름>`)** 가 있는지도 본다.

**Git 이력**도 확인한다(현재 파일에서 지웠어도 이력에 남아 있으면 공개 시 노출된다):

```bash
git log --all --diff-filter=A --name-only --pretty=format: | sort -u | grep -iE '(^|/)\.env($|\.)|\.pem$|\.key$|id_rsa|credentials|service-account'
git log --all -p | grep -cE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk_live_|-----BEGIN [A-Z ]*PRIVATE KEY-----|service_role'
```

이력 전체 검사는 큰 저장소에서 느릴 수 있으므로, 시간이 오래 걸리면 범위(최근 N개 커밋)를 줄이고 그 사실을 보고서에 적는다. `gitleaks`·`trufflehog`가 설치돼 있으면 사용을 **제안**하되(설치는 승인 후), 출력에 값이 나오지 않도록 `--redact` 옵션을 쓴다.

### 3. `.gitignore` 검토

```bash
cat .gitignore
git check-ignore -v .env .env.local .venv node_modules __pycache__ .DS_Store 2>/dev/null
git ls-files -ci --exclude-standard   # 무시 규칙에 해당하는데 이미 추적 중인 파일
```

- 프로젝트 스택에 맞는 필수 항목(`.env`, `.env.*` + `!.env.example`, 가상환경, `node_modules/`, 빌드 산출물, 로그, 로컬 DB, IDE 설정, OS 파일)이 있는지 본다.
- `.gitignore`에 있는데 이미 추적 중인 파일은 무시되지 않는다는 점을 지적한다.
- 작업 트리에 존재하는 민감 파일(예: `.env`)이 실제로 ignore 되는지 `git check-ignore`로 확인한다.

### 4. README 문서 확인

README(대소문자·확장자 무관)를 읽고 다음 항목의 존재 여부를 표로 정리한다.

| 항목 | 확인 기준 |
|---|---|
| 프로젝트 설명 | 무엇을, 왜 만들었는지 첫 부분에 있는가 |
| 설치 방법 | 의존성 설치 명령, 필요한 런타임/버전 |
| 실행 방법 | 로컬 실행 명령, 접속 주소 |
| 환경변수 안내 | `.env.example` 등 예시 파일과 설명(실제 값 없이) |
| 테스트 방법 | 있으면 좋음 |
| 라이선스 | `LICENSE` 파일 또는 README 언급 — 없으면 "공개 저장소라도 기본적으로 재사용 불가"임을 안내 |

README 안에 실제 키, 개인 이메일, 로컬 절대경로가 있는지도 2단계 기준으로 본다.

### 5. 커밋 예정 변경사항의 민감 파일 확인

```bash
git diff --cached --name-status          # 스테이징됨
git diff --name-status                   # 수정됐지만 스테이징 안 됨
git ls-files --others --exclude-standard # 추적 안 되는 새 파일 (다음 git add . 때 들어갈 후보)
git log --branches --not --remotes --name-status --oneline  # 아직 push 안 된 커밋
```

이 목록에 `.env`, 키 파일, 설정 파일(`config.*`, `settings*.json`, `*.yaml` 중 비밀 포함 가능 파일), 데이터 덤프가 있으면 기록하고, 해당 파일에 2단계 검색을 다시 적용한다(값은 출력하지 않는다).

### 6. 위험 분류

| 등급 | 기준 | 예시 |
|---|---|---|
| 🔴 Critical | 공개 즉시 악용 가능한 실제 비밀 | 추적 중인 `.env`, 서비스 롤/관리자 키, 개인키, 이력에 남은 실제 토큰, 주민번호 |
| 🟠 High | 공개 시 노출 가능성이 높음 | 스테이징된 민감 파일, `.gitignore` 누락으로 `git add .` 시 들어갈 비밀 파일, 실제 개인 이메일·전화번호 |
| 🟡 Medium | 정보 노출·관리 문제 | 로컬 절대경로·사용자명, 내부 URL, 실명/회사명, 데이터 덤프, 라이선스 없음 |
| 🔵 Low | 문서·위생 개선 | README 설치/실행 방법 누락, `.env.example` 설명 부족 |
| ✅ 확인됨 | 점검했고 문제 없음 | `.env`는 ignore 되어 추적되지 않음 |

판단이 불확실하면 한 단계 높은 등급으로 두고 "확인 필요"를 붙인다.

### 7. 보고서 출력

아래 형식으로 대화에 출력한다. 사용자가 파일 저장을 요청한 경우에만 파일로 쓴다.

```markdown
# GitHub 공개 전 점검 보고서 — <프로젝트 폴더명>
점검 일시: <YYYY-MM-DD> · 브랜치: <branch> · 원격: <있음/없음, 공개 여부>

## 결론
<공개 가능 / 조치 후 공개 / 공개 보류> — 한두 문장 근거

## 발견 사항
| 등급 | 항목 | 위치 | 근거 (값 미표기) | 권장 조치 |
|---|---|---|---|---|

## 단계별 결과
1. Git 상태: ...
2. 비밀정보/개인정보: ...
3. .gitignore: ...
4. README: (항목별 ✅/❌ 표)
5. 커밋 예정 변경: ...

## 검사 범위와 한계
- 검사 대상: <추적 파일 N개, 이력 커밋 N개, 미추적 파일 여부>
- 사용한 방법: 정규식 패턴 검색(git grep / git log -p), 파일명 규칙, 문서 수동 확인
- 발견하지 못할 수 있는 것: 패턴에 맞지 않는 비밀(임의 문자열 비밀번호, 인코딩/분할된 값), 이미지·PDF·바이너리 내부, 서브모듈, Git LFS 객체, 포크·PR·이슈·Actions 로그 등 GitHub 쪽 데이터
- 이 보고서는 위험을 줄이기 위한 보조 도구이며 비밀정보가 없음을 보증하지 않는다.

## 승인이 필요한 다음 조치
- [ ] <예: .env를 git rm --cached로 추적 해제 후 커밋> 
- [ ] <예: 노출된 키 재발급(rotate) — 이력에서 지워도 이미 공개된 키는 폐기해야 함>
```

보고서를 출력한 뒤, 사용자가 승인한 조치만 하나씩 수행한다. 이미 공개된 키가 발견되면 "이력 삭제보다 키 폐기·재발급이 먼저"라고 안내한다.
