# PwN-Chain (폰체인)

**Gemini와 함께 개발한 CTF/워게임용 차세대 바이너리 분석 도우미**

PwN-Chain은 `pwndbg`의 편리함과 현대적인 CLI의 미학을 결합하여, 바이너리 취약점 분석 및 익스플로잇 과정을 효율적으로 만들어주는 AI 기반의 보조 도구입니다.

---

### 주요 기능 (Features)

- **pwndbg 스타일 CLI**: `pwnchain>` 프롬프트에 명령어를 입력하고 그 결과를 즉시 확인하는 직관적인 인터페이스를 제공합니다.
- **AI 분석 가이드**: 바이너리 로드 시 `checksec` 정보와 위험 함수 사용 여부를 바탕으로 잠재적 취약점과 분석 접근법을 자동으로 제안합니다.
- **실시간 디버깅 뷰**: GDB와 연동하여 `step`, `next` 등의 명령 실행 후, 현재 코드의 디스어셈블리, 스택, 레지스터 상태를 자동으로 시각화하여 보여줍니다.
- **원격 분석 지원**: SSH를 통해 원격 서버에 접속(`connect`), 파일을 업로드(`upload`)하고, 원격지의 바이너리를 직접 분석(`load`, `run`, `gdb`)할 수 있습니다.
- **익스플로잇 코드 생성**: 현재 분석 중인 바이너리의 컨텍스트(아키텍처, 주소 등)를 바탕으로 `pwntools` 기반의 익스플로잇 템플릿을 자동으로 생성(`exploit`)합니다.
- **미려한 UI/UX**: ASCII 아트 배너와 커스텀 테마를 적용하여 세련된 "해커 스타일"의 터미널 환경을 제공합니다.

---

### 설치 및 실행 방법 (Installation & Usage)

1.  **리포지토리 클론:**
    ```bash
    git clone https://github.com/HOHK0923/PwN-Chain.git
    cd PwN-Chain
    ```

2.  **가상환경 생성 및 라이브러리 설치:**
    ```bash
    # 가상환경 생성 (최초 1회)
    python3 -m venv venv

    # 라이브러리 설치 (최초 1회)
    ./venv/bin/pip install -r requirements.txt
    ```

3.  **PwnChain 명령어 설치:**
    아래 명령어를 실행하여 `PwnChain`을 전역 명령어로 등록합니다.
    ```bash
    # 개발 모드(-e)로 설치
    ./venv/bin/pip install -e .
    ```

4.  **실행:**
    터미널에서 가상환경을 활성화한 후, `PwnChain` 명령어를 실행합니다.
    ```bash
    # 가상환경 활성화
    source venv/bin/activate

    # PwnChain 실행
    PwnChain
    ```
    이제 `pwnchain>` 프롬프트가 나타나며 도구를 사용할 수 있습니다.

---

### 주요 명령어 (Commands)

`pwnchain>` 프롬프트에서 `help`를 입력하면 모든 명령어를 확인할 수 있습니다.

- `connect <user@host>`: 원격 서버에 연결합니다.
- `load <path>`: 바이너리를 로드하고 정적 분석 및 AI 가이드를 받습니다.
- `run`: 로드된 바이너리를 실행합니다.
- `gdb`: 실행 중인 프로세스에 GDB를 연결하고 디버깅 뷰를 활성화합니다.
- `c` / `n` / `s` / `b <target>`: GDB를 제어합니다. (continue, next, step, break)
- `exploit`: 익스플로잇 코드 템플릿을 생성합니다.

---

### **주의사항 (Disclaimer)**

**본 도구는 교육 및 연구 목적으로만 사용되어야 합니다.**
(**This tool is intended for educational and research purposes only.**)