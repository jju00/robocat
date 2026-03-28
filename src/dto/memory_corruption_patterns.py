"""
Memory corruption pattern dictionary.
이 파일은 postprocess_memory_patterns.py가 확장/갱신할 수 있다.
"""

from __future__ import annotations

MEMORY_CORRUPTION_PATTERNS = [
    {
        "name": "Buffer Overflow",
        "aliases": [
            "buffer overflow",
            "classic buffer overflow",
            "bof",
            "buffer overrun",
            "unbounded transfer",
            "stack buffer overflow",
            "stack-based buffer overflow",
            "heap buffer overflow",
            "heap-based buffer overflow"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-120",
            "CWE-121",
            "CWE-122"
        ],
        "representative_pattern": "고정 크기 버퍼에 입력 길이 또는 복사 크기 검증 없이 데이터를 복사하거나 써서 경계를 넘기는 패턴",
        "representative_code_examples": [
            "char buf[16]; strcpy(buf, input);",
            "char dst[32]; memcpy(dst, src, user_len);",
            "char name[8]; sprintf(name, \"%s\", user_input);"
        ],
        "common_indicators": [
            "고정 길이 배열 사용",
            "길이 체크 없는 strcpy/memcpy/sprintf 계열",
            "입력 길이 신뢰",
            "반복문 경계 검증 누락"
        ]
    },
    {
        "name": "Out-of-Bounds Write",
        "aliases": [
            "out-of-bounds write",
            "out of bounds write",
            "oob write",
            "buffer overwrite",
            "write past end of buffer"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-787"
        ],
        "representative_pattern": "배열이나 버퍼의 유효 범위를 넘는 위치에 데이터를 기록하는 패턴",
        "representative_code_examples": [
            "buf[index] = value;  // index >= size",
            "for (int i = 0; i <= len; ++i) dst[i] = src[i];",
            "ptr[offset] = 0;  // offset 검증 없음"
        ],
        "common_indicators": [
            "index 상한 검증 없음",
            "<= 사용으로 마지막 경계 초과",
            "길이 계산 실수",
            "포인터 산술 후 쓰기"
        ]
    },
    {
        "name": "Out-of-Bounds Read",
        "aliases": [
            "out-of-bounds read",
            "out of bounds read",
            "oob read",
            "buffer over-read",
            "buffer overread",
            "read past end of buffer",
            "overread"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-125",
            "CWE-126"
        ],
        "representative_pattern": "배열이나 버퍼의 유효 범위를 넘는 위치의 데이터를 읽는 패턴",
        "representative_code_examples": [
            "char c = buf[index];  // index >= size",
            "memcmp(buf, other, attacker_len);",
            "while (buf[i] != '\\0') { use(buf[i++]); }  // 종단 보장 없음"
        ],
        "common_indicators": [
            "index 검증 없는 읽기",
            "길이보다 큰 범위 비교",
            "널 종료 가정",
            "버퍼 끝 이후 데이터 참조"
        ]
    },
    {
        "name": "Buffer Underwrite",
        "aliases": [
            "buffer underwrite",
            "buffer underrun",
            "underwrite",
            "write before buffer"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-124"
        ],
        "representative_pattern": "버퍼 시작 주소보다 앞선 메모리 영역에 데이터를 쓰는 패턴",
        "representative_code_examples": [
            "char *p = buf - 1; *p = 'A';",
            "dst[index - 1] = value;  // index == 0 가능"
        ],
        "common_indicators": [
            "음수 오프셋",
            "시작 전 위치 쓰기",
            "포인터 감소 후 기록"
        ]
    },
    {
        "name": "Off-by-One Error",
        "aliases": [
            "off-by-one",
            "off by one",
            "obo",
            "boundary error"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-193"
        ],
        "representative_pattern": "반복문 종료 조건이나 길이 계산이 한 칸 어긋나 버퍼 마지막 경계를 넘는 패턴",
        "representative_code_examples": [
            "for (int i = 0; i <= size; ++i) buf[i] = 0;",
            "char dst[8]; strncpy(dst, src, 8); dst[8] = '\\0';"
        ],
        "common_indicators": [
            "< 와 <= 혼동",
            "널 종료 문자 공간 미고려",
            "size + 1 / size - 1 계산 실수"
        ]
    },
    {
        "name": "Use After Free",
        "aliases": [
            "use after free",
            "use-after-free",
            "uaf",
            "dangling pointer dereference",
            "access to freed memory"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-416"
        ],
        "representative_pattern": "해제된 메모리를 가리키는 포인터를 이후에 다시 읽거나 쓰거나 호출에 사용하는 패턴",
        "representative_code_examples": [
            "free(ptr); printf(\"%s\", ptr);",
            "free(obj); obj->field = 1;",
            "delete p; p->run();"
        ],
        "common_indicators": [
            "free/delete 이후 동일 포인터 사용",
            "해제 후 NULL 처리 없음",
            "소유권 관리 불명확"
        ]
    },
    {
        "name": "Double Free",
        "aliases": [
            "double free",
            "double-free",
            "duplicate free"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-415"
        ],
        "representative_pattern": "동일한 힙 메모리 블록을 두 번 이상 해제하는 패턴",
        "representative_code_examples": [
            "free(ptr); free(ptr);",
            "delete p; if (error) delete p;"
        ],
        "common_indicators": [
            "에러 경로와 정상 경로에서 중복 해제",
            "참조 카운트 관리 실패",
            "해제 후 NULL 대입 누락"
        ]
    },
    {
        "name": "Invalid Free",
        "aliases": [
            "invalid free",
            "bad free",
            "free of non-heap memory",
            "free stack pointer",
            "free of invalid pointer"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-590",
            "CWE-761",
            "CWE-763"
        ],
        "representative_pattern": "힙에서 올바르게 할당되지 않았거나 원래 시작 주소가 아닌 포인터를 해제하는 패턴",
        "representative_code_examples": [
            "char buf[16]; free(buf);",
            "char *p = malloc(32); free(p + 1);"
        ],
        "common_indicators": [
            "스택 메모리 free",
            "중간 포인터 free",
            "할당/해제 쌍 불일치"
        ]
    },
    {
        "name": "Null Pointer Dereference",
        "aliases": [
            "null pointer dereference",
            "null dereference",
            "null deref",
            "null-deref",
            "dereference of null pointer",
            "npd"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-476"
        ],
        "representative_pattern": "NULL 이 될 수 있는 포인터에 대해 유효성 검사 없이 역참조하는 패턴",
        "representative_code_examples": [
            "node = find(id); return node->value;",
            "char *p = getenv(\"X\"); printf(\"%c\", p[0]);"
        ],
        "common_indicators": [
            "함수 반환 포인터 NULL 체크 없음",
            "에러 경로 누락",
            "조건 분기 후 널 가능성 남아 있음"
        ]
    },
    {
        "name": "Format String Bug",
        "aliases": [
            "format string",
            "format string bug",
            "format string vulnerability",
            "uncontrolled format string",
            "fsb"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-134"
        ],
        "representative_pattern": "사용자 제어 문자열이 그대로 포맷 문자열로 사용되어 메모리 읽기·쓰기나 비정상 동작을 유발하는 패턴",
        "representative_code_examples": [
            "printf(user_input);",
            "fprintf(log, argv[1]);",
            "syslog(LOG_ERR, msg);"
        ],
        "common_indicators": [
            "printf 계열 첫 번째 인자에 외부 입력",
            "%n 악용 가능성",
            "고정 포맷 문자열 부재"
        ]
    },
    {
        "name": "Integer Overflow or Wraparound",
        "aliases": [
            "integer overflow",
            "int overflow",
            "overflow wraparound",
            "signed overflow",
            "wraparound"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-190"
        ],
        "representative_pattern": "정수 계산 결과가 표현 범위를 넘어 크기 계산, 인덱스 계산, 할당 크기 산정이 잘못되는 패턴",
        "representative_code_examples": [
            "size_t total = count * elem_size; char *p = malloc(total);",
            "int len = a + b; char *buf = malloc(len);"
        ],
        "common_indicators": [
            "할당 크기 계산식",
            "곱셈/덧셈 후 범위 검사 없음",
            "signed/unsigned 혼용"
        ]
    },
    {
        "name": "Integer Underflow",
        "aliases": [
            "integer underflow",
            "int underflow",
            "negative wraparound"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-191"
        ],
        "representative_pattern": "정수 감소나 뺄셈 결과가 최소 범위를 지나 인덱스나 길이 값이 비정상적으로 변하는 패턴",
        "representative_code_examples": [
            "size_t n = len - 1; memcpy(dst, src, n);  // len == 0 가능",
            "int remain = end - start; buf[remain] = 0;"
        ],
        "common_indicators": [
            "0 미만 가능성 검증 없음",
            "size_t 로 승격되며 큰 값으로 변환",
            "길이 감소 후 바로 사용"
        ]
    },
    {
        "name": "Incorrect Calculation of Buffer Size",
        "aliases": [
            "incorrect calculation of buffer size",
            "incorrect buffer size",
            "buffer size miscalculation",
            "size calculation bug",
            "cwe-131"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-131"
        ],
        "representative_pattern": "필요한 버퍼 크기를 잘못 계산해 실제 데이터보다 작은 메모리를 할당하거나 사용하는 패턴",
        "representative_code_examples": [
            "char *p = malloc(strlen(src)); strcpy(p, src);",
            "malloc(count * sizeof(ptr));  // sizeof(*ptr)여야 함"
        ],
        "common_indicators": [
            "널 종료 문자 공간 누락",
            "sizeof 대상 실수",
            "개수 × 원소 크기 계산 오류"
        ]
    },
    {
        "name": "Heap Corruption",
        "aliases": [
            "heap corruption",
            "corrupted heap",
            "heap metadata corruption"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-122",
            "CWE-787",
            "CWE-415",
            "CWE-416"
        ],
        "representative_pattern": "힙 청크 경계나 메타데이터를 손상시켜 이후 할당·해제 동작을 비정상적으로 만드는 패턴",
        "representative_code_examples": [
            "char *p = malloc(16); memset(p, 'A', 64);",
            "free(ptr); free(ptr);  // allocator metadata 손상 가능"
        ],
        "common_indicators": [
            "힙 버퍼 초과 쓰기",
            "잘못된 free",
            "allocator crash/malloc corruption 로그"
        ]
    },
    {
        "name": "Stack Overflow",
        "aliases": [
            "stack overflow",
            "stack exhaustion",
            "unbounded recursion overflow"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-674",
            "CWE-121"
        ],
        "representative_pattern": "재귀 폭주나 과도한 스택 사용으로 스택 영역을 소진하거나 손상시키는 패턴",
        "representative_code_examples": [
            "void f() { char buf[1000000]; f(); }",
            "int dfs(Node *n) { return dfs(n->next); }"
        ],
        "common_indicators": [
            "종료 조건 없는 재귀",
            "매우 큰 지역 배열",
            "깊은 호출 체인"
        ]
    },
    {
        "name": "Uninitialized Memory Use",
        "aliases": [
            "uninitialized memory",
            "use of uninitialized memory",
            "uninitialized read",
            "uninit read"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-457",
            "CWE-908"
        ],
        "representative_pattern": "초기화되지 않은 스택·힙 메모리를 읽거나 로직 판단에 사용하는 패턴",
        "representative_code_examples": [
            "int flag; if (flag) grant();",
            "char *p = malloc(32); send(sock, p, 32, 0);"
        ],
        "common_indicators": [
            "선언 후 초기화 없음",
            "malloc 후 memset 누락",
            "조건식에 미초기화 변수 사용"
        ]
    },
    {
        "name": "Dangling Pointer",
        "aliases": [
            "dangling pointer",
            "stale pointer",
            "wild pointer after free"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-416",
            "CWE-825"
        ],
        "representative_pattern": "유효 수명이 끝난 객체를 계속 가리키는 포인터가 남아 이후 오류를 유발하는 패턴",
        "representative_code_examples": [
            "char *p = get_buffer(); release_buffer(); return p;",
            "free(node); list->current = node;"
        ],
        "common_indicators": [
            "해제 후 포인터 보존",
            "스코프 종료 객체 주소 반환",
            "소유권 이전 후 이전 참조 유지"
        ]
    },
    {
        "name": "Type Confusion",
        "aliases": [
            "type confusion",
            "confused type",
            "bad cast memory access"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-843"
        ],
        "representative_pattern": "실제 객체 타입과 다른 타입으로 해석해 잘못된 오프셋이나 필드에 접근하는 패턴",
        "representative_code_examples": [
            "Base *obj = get_obj(); Derived *d = (Derived *)obj; d->field = 1;",
            "void *p = get_any(); ((Header *)p)->len = 8;"
        ],
        "common_indicators": [
            "강제 캐스팅",
            "태그/타입 검증 누락",
            "다형 객체의 잘못된 다운캐스트"
        ]
    },
    {
        "name": "Write-What-Where Condition",
        "aliases": [
            "write-what-where",
            "arbitrary write",
            "attacker controlled write",
            "www"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-123"
        ],
        "representative_pattern": "공격자가 쓸 값과 쓸 위치를 모두 제어할 수 있게 되는 패턴",
        "representative_code_examples": [
            "*user_ptr = user_value;",
            "memcpy(target_addr, src, len);  // target_addr 제어 가능"
        ],
        "common_indicators": [
            "포인터 무결성 검증 없음",
            "임의 주소 쓰기",
            "간접 참조 대상이 외부 입력"
        ]
    },
    {
        "name": "Read-What-Where Condition",
        "aliases": [
            "read-what-where",
            "arbitrary read",
            "attacker controlled read"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-125",
            "CWE-822"
        ],
        "representative_pattern": "공격자가 읽을 위치를 제어해 임의 메모리 내용을 노출시키는 패턴",
        "representative_code_examples": [
            "printf(\"%x\", *user_ptr);",
            "copy_to_user(out, kernel_ptr, len);  // kernel_ptr 검증 불충분"
        ],
        "common_indicators": [
            "외부 입력 포인터 역참조",
            "메모리 내용 정보 유출",
            "주소 검증 부재"
        ]
    },
    {
        "name": "Memory Leak",
        "aliases": [
            "memory leak",
            "leak",
            "lost allocation",
            "resource leak memory"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-401"
        ],
        "representative_pattern": "할당한 메모리를 적절히 해제하지 않아 장기 실행 시 메모리 고갈이나 서비스 불안정을 일으키는 패턴",
        "representative_code_examples": [
            "char *p = malloc(1024); return;  // free 없음",
            "while (1) list_add(malloc(sizeof(Node)));"
        ],
        "common_indicators": [
            "에러 경로 free 누락",
            "소유권 불명확",
            "루프 내 반복 할당"
        ]
    },
    {
        "name": "Improper Length Validation",
        "aliases": [
            "improper length validation",
            "length validation bug",
            "insufficient bounds check",
            "size check missing"
        ],
        "category": "memory_corruption",
        "cwe_ids": [
            "CWE-1284",
            "CWE-119"
        ],
        "representative_pattern": "입력 길이, 개수, 오프셋을 충분히 검증하지 않아 이후 복사·할당·인덱싱 단계에서 메모리 오류로 이어지는 패턴",
        "representative_code_examples": [
            "if (len < MAX) memcpy(dst, src, user_len);  // 실제 검증 대상 불일치",
            "read(fd, buf, packet.len);  // packet.len 신뢰"
        ],
        "common_indicators": [
            "외부 길이 필드 신뢰",
            "검사와 사용 대상 불일치",
            "상한/하한 둘 중 하나만 검사"
        ]
    },
    {
        "name": "SQL Injection",
        "aliases": [
            "sql injection",
            "sqli",
            "sql 삽입",
            "structured query language injection"
        ],
        "category": "injection",
        "cwe_ids": [
            "CWE-89"
        ],
        "representative_pattern": "사용자 입력을 쿼리 문자열에 직접 결합하거나 파라미터 바인딩 없이 처리해 SQL 구조가 변조될 수 있는 패턴",
        "representative_code_examples": [
            "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";",
            "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)"
        ],
        "common_indicators": [
            "문자열 기반 쿼리 조합",
            "파라미터 바인딩 미사용",
            "사용자 입력 직접 연결",
            "WHERE 절에 외부 입력 삽입"
        ]
    },
    {
        "name": "Code Injection",
        "aliases": [
            "code injection",
            "코드 주입"
        ],
        "category": "injection",
        "cwe_ids": [
            "CWE-94"
        ],
        "representative_pattern": "외부 입력이 코드 조각으로 해석되거나 실행되어 의도하지 않은 명령이 수행될 수 있는 패턴",
        "representative_code_examples": [
            "eval(user_input)",
            "exec(user_input)"
        ],
        "common_indicators": [
            "eval/exec 사용",
            "동적 코드 생성",
            "외부 입력을 코드로 해석"
        ]
    },
    {
        "name": "Injection",
        "aliases": [
            "injection",
            "injection attack"
        ],
        "category": "injection",
        "cwe_ids": [
            "CWE-74"
        ],
        "representative_pattern": "신뢰할 수 없는 입력이 해석기나 명령 실행 맥락에 직접 삽입되어 구조를 바꾸는 패턴",
        "representative_code_examples": [
            "interpreter.run(user_input)",
            "command = prefix + user_input"
        ],
        "common_indicators": [
            "해석기 입력 직접 결합",
            "명령 구성 문자열 조합",
            "입력 검증과 인코딩 부족"
        ]
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "aliases": [
            "xss",
            "cross site scripting",
            "cross-site scripting",
            "크로스 사이트 스크립팅"
        ],
        "category": "xss",
        "cwe_ids": [
            "CWE-79"
        ],
        "representative_pattern": "사용자 입력을 적절히 인코딩하거나 필터링하지 않고 HTML 또는 DOM 맥락에 반영해 스크립트가 실행되는 패턴",
        "representative_code_examples": [
            "response.write('<div>' + user_input + '</div>');",
            "document.body.innerHTML += user_input;"
        ],
        "common_indicators": [
            "출력 인코딩 누락",
            "innerHTML 사용",
            "사용자 입력 직접 렌더링",
            "스크립트 태그 또는 이벤트 핸들러 삽입 가능"
        ]
    },
    {
        "name": "Cross-Site Request Forgery (CSRF)",
        "aliases": [
            "csrf",
            "cross site request forgery",
            "cross-site request forgery",
            "사이트 간 요청 위조"
        ],
        "category": "csrf",
        "cwe_ids": [
            "CWE-352"
        ],
        "representative_pattern": "상태 변경 요청에 대해 출처 검증이나 토큰 검증이 부족해 사용자가 의도하지 않은 요청을 보내게 되는 패턴",
        "representative_code_examples": [
            "app.post('/transfer', (req, res) => { /* state change */ });",
            "<form action='/delete' method='POST'>...</form>"
        ],
        "common_indicators": [
            "CSRF 토큰 누락",
            "Origin/Referer 검증 없음",
            "상태 변경 POST 요청 보호 부족"
        ]
    },
    {
        "name": "Directory Traversal",
        "aliases": [
            "directory traversal",
            "path traversal",
            "directory climbing",
            "path traversal vulnerability"
        ],
        "category": "path_traversal",
        "cwe_ids": [
            "CWE-22"
        ],
        "representative_pattern": "상대 경로나 상위 디렉터리 참조를 포함한 입력을 적절히 제한하지 않아 의도한 디렉터리 밖 파일에 접근하는 패턴",
        "representative_code_examples": [
            "open(user_path, 'r')",
            "readFile('../config/settings.py')"
        ],
        "common_indicators": [
            "../ 시퀀스 허용",
            "기준 디렉터리 제한 없음",
            "경로 정규화 부족"
        ]
    },
    {
        "name": "Open Redirect",
        "aliases": [
            "open redirect",
            "url redirection vulnerability",
            "unvalidated redirect"
        ],
        "category": "open_redirect",
        "cwe_ids": [
            "CWE-601"
        ],
        "representative_pattern": "사용자 제어 URL을 검증 없이 리다이렉트 대상으로 사용해 악성 사이트로 이동시킬 수 있는 패턴",
        "representative_code_examples": [
            "redirect_url = request.args.get('url')",
            "return redirect(redirect_url)"
        ],
        "common_indicators": [
            "사용자 입력 기반 Location 헤더",
            "허용 도메인 검증 없음",
            "리다이렉트 대상 화이트리스트 부재"
        ]
    },
    {
        "name": "Improper Access Control",
        "aliases": [
            "improper access control",
            "access control vulnerability",
            "authorization flaw",
            "broken access control"
        ],
        "category": "access_control",
        "cwe_ids": [
            "CWE-284"
        ],
        "representative_pattern": "권한 검사를 누락하거나 잘못 적용해 인가되지 않은 사용자가 기능이나 데이터에 접근할 수 있게 되는 패턴",
        "representative_code_examples": [
            "if (user.is_admin()) { showAdminPanel(); }",
            "if (request.user_id == target_id) updateProfile();"
        ],
        "common_indicators": [
            "권한 확인 누락",
            "서버 측 인가 검증 부족",
            "객체 수준 접근 통제 부재"
        ]
    },
    {
        "name": "Improper Input Validation",
        "aliases": [
            "improper input validation",
            "insufficient input validation",
            "input validation flaw",
            "부적절한 입력 검증"
        ],
        "category": "input_validation",
        "cwe_ids": [
            "CWE-20"
        ],
        "representative_pattern": "입력의 길이, 형식, 범위, 허용 값 집합을 충분히 검증하지 않아 후속 로직에서 보안 문제가 발생하는 패턴",
        "representative_code_examples": [
            "process(user_input)",
            "if len(data) < 100: store(data)"
        ],
        "common_indicators": [
            "허용 값 검증 없음",
            "길이/형식 검사 부족",
            "서버 측 검증 누락"
        ]
    },
    {
        "name": "Insecure Communication",
        "aliases": [
            "insecure communication",
            "unsecured data transmission",
            "cleartext transmission"
        ],
        "category": "insecure_communication",
        "cwe_ids": [
            "CWE-319"
        ],
        "representative_pattern": "민감한 데이터를 암호화되지 않은 채 전송하거나 서버 신뢰성을 충분히 검증하지 않아 도청·변조 위험이 생기는 패턴",
        "representative_code_examples": [
            "requests.get('http://example.com')",
            "socket.send(data)"
        ],
        "common_indicators": [
            "HTTP 사용",
            "TLS 미사용",
            "인증서 검증 비활성화"
        ]
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "aliases": [
            "ssrf",
            "server-side request forgery",
            "server side request forgery",
            "서버 측 요청 위조"
        ],
        "category": "ssrf",
        "cwe_ids": [
            "CWE-918"
        ],
        "representative_pattern": "서버가 외부 입력으로 지정된 URL로 요청을 보내 내부 네트워크나 민감한 자원에 접근하게 되는 패턴",
        "representative_code_examples": [
            "requests.get(user_input_url)",
            "fetch(remote_url)"
        ],
        "common_indicators": [
            "사용자 입력 기반 URL 요청",
            "대상 호스트 검증 없음",
            "내부 주소 대역 차단 부재"
        ]
    },
    {
        "name": "Improper Session Management",
        "aliases": [
            "improper session management",
            "improper session handling",
            "세션 관리 부적절"
        ],
        "category": "session_management",
        "cwe_ids": [
            "CWE-384"
        ],
        "representative_pattern": "세션 식별자 생성, 갱신, 만료, 저장이 부적절해 세션 탈취나 고정 공격 위험이 생기는 패턴",
        "representative_code_examples": [
            "session['user_id'] = user.id",
            "if session['is_active']: pass"
        ],
        "common_indicators": [
            "세션 재생성 누락",
            "세션 만료 정책 부족",
            "민감 세션 속성 보호 부족"
        ]
    },
    {
        "name": "Session Fixation",
        "aliases": [
            "session fixation",
            "session fixation attack",
            "세션 고정"
        ],
        "category": "session_management",
        "cwe_ids": [
            "CWE-384"
        ],
        "representative_pattern": "공격자가 미리 정한 세션 식별자를 사용자가 그대로 쓰게 만들어 인증 후 세션을 가로채는 패턴",
        "representative_code_examples": [
            "session_id = request.GET.get('session_id')",
            "authenticate_user(session_id)"
        ],
        "common_indicators": [
            "로그인 후 세션 ID 재발급 없음",
            "URL 기반 세션 ID 허용",
            "고정 세션 재사용"
        ]
    },
    {
        "name": "Insecure Cookie Handling",
        "aliases": [
            "insecure cookie handling",
            "insecure cookie management",
            "weak cookie security"
        ],
        "category": "cookie_security",
        "cwe_ids": [
            "CWE-614"
        ],
        "representative_pattern": "쿠키에 대한 Secure, HttpOnly, SameSite 같은 보호 속성이나 저장 내용 관리가 미흡해 세션 탈취나 노출 위험이 생기는 패턴",
        "representative_code_examples": [
            "response.set_cookie('session_id', 'abc123')",
            "cookie_value = request.cookies.get('session_id')"
        ],
        "common_indicators": [
            "Secure 속성 없음",
            "HttpOnly 누락",
            "민감 정보 쿠키 저장"
        ]
    },
    {
        "name": "CSV Injection",
        "aliases": [
            "csv injection",
            "formula injection",
            "csv 주입"
        ],
        "category": "csv_injection",
        "cwe_ids": [
            "CWE-1236"
        ],
        "representative_pattern": "스프레드시트에서 수식으로 해석될 수 있는 값을 CSV에 그대로 내보내 파일 열람 시 의도치 않은 동작이 발생하는 패턴",
        "representative_code_examples": [
            "row = ['=CMD()', user_email]",
            "write_csv([user_supplied_value])"
        ],
        "common_indicators": [
            "=,+,-,@ 로 시작하는 셀 값",
            "내보내기 전 이스케이프 부족",
            "사용자 입력 직접 CSV 기록"
        ]
    }
]


def normalize_vulnerability_name(name: str) -> str:
    if not name:
        return ""
    text = str(name).strip().lower()
    text = text.replace("_", " ").replace("-", " ")
    import re
    text = re.sub(r"\s+", " ", text)
    return text


def find_memory_corruption_pattern(name: str):
    if not name:
        return None

    target = normalize_vulnerability_name(name)

    for item in MEMORY_CORRUPTION_PATTERNS:
        names = [item.get("name", ""), *item.get("aliases", [])]
        normalized = [normalize_vulnerability_name(x) for x in names if x]
        if target in normalized:
            return item

    for item in MEMORY_CORRUPTION_PATTERNS:
        names = [item.get("name", ""), *item.get("aliases", [])]
        normalized = [normalize_vulnerability_name(x) for x in names if x]
        for candidate in normalized:
            if candidate and (candidate in target or target in candidate):
                return item

    return None
