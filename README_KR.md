# ReplayShield-PAM

ReplayShield는 PAM(예: SSH) 인증 과정에서 최근에 사용된 암호를 거부하여 재사용 공격을 막아 주는 경량 HTTP 인증 서비스입니다. 사용자별 암호 풀과 사용 이력을 저장하고, 설정된 윈도우(`block_count`) 안에서 재사용된 암호를 자동으로 차단합니다.

## 주요 기능

- `replayshield init/manage/password/serve` CLI로 초기화, 사용자/암호 풀 관리, 관리자 키 캐싱, HTTP 서버 실행을 한 번에 수행.
- 사용자별 암호 히스토리(힌트, 적중 횟수, 차단 여부, 최근 사용 시각) 관리.
- 암호화된 SQLite DB: 디스크에는 항상 암호화된 상태로 저장되고 `/dev/shm` tmpfs에서만 복호화.
- `/auth` HTTP POST 엔드포인트가 `PASS`/`FAIL`을 반환하여 PAM 스크립트가 인증 결과로 활용.
- `pam_exec.so expose_authtok`와 연동되는 PAM 스크립트(`/usr/lib/replayshield/replayshield-pam.sh`) 및 Google OTP 등 다른 모듈과의 조합 지원.
- `/usr/bin/replayshield` 래퍼, systemd 서비스, Debian 패키징 스크립트 포함.

## 1. 설치

### 소스에서 빌드

요구 사항: JDK 21, Gradle wrapper.

```bash
./gradlew clean shadowJar
```

실행 가능한 JAR는 `build/libs/replayshield.jar`에 생성됩니다.

### Debian 패키지

`.deb` 패키지를 빌드하여 시스템에 설치할 수 있습니다.

```bash
./packaging/build-deb.sh
sudo dpkg -i release/replayshield_*.deb
```

설치 후 `/usr/bin/replayshield`, `/usr/lib/replayshield/replayshield-pam.sh`, `replayshield.service`가 배포됩니다.
또한 `/usr/share/bash-completion/completions/replayshield`에 bash 자동완성 스크립트가 설치되어 `replayshield <TAB>` 입력 시 `init/manage/password/serve` 등이 자동 완성됩니다.

## 2. 각종 설정

1. **PAM 설정**
   - `/etc/pam.d/sshd` 등에 다음 줄을 추가합니다.
     ```
     auth required pam_exec.so quiet expose_authtok /usr/lib/replayshield/replayshield-pam.sh
     ```
   - 기본 `@include common-auth/account/session` 라인이 필요하면 주석 해제하여 기존 시스템 검사가 그대로 수행되도록 합니다.
   - Google OTP 등 다른 모듈을 추가하려면 ReplayShield 라인 앞뒤에 배치합니다.
2. **systemd / 환경 변수**
   - 기본 HTTP 서버는 `127.0.0.1:4444`에서 동작합니다. 필요하면 `/etc/default/replayshield` 혹은 systemd override로 환경 변수를 조정합니다.
3. **파일 시스템**
   - `/dev/shm` 이 tmpfs인지 확인합니다. (암호화 해제된 파일이 여기에만 위치함)
   - `/etc/replayshield`, `/var/lib/replayshield`의 권한을 root 전용으로 유지합니다.

## 3. 실행

1. **초기화 & 관리**
   ```bash
   sudo replayshield init      # salt와 암호화 DB 생성 (재실행 시 전체 초기화)
   sudo replayshield manage    # 사용자/암호 풀 관리, block_count 조정, 디버그 출력
   ```
2. **관리자 암호 캐시**
   ```bash
   sudo replayshield password
   ```
   - `/dev/shm/replayshield/admin.key` 에 관리자 암호를 RAM에 저장합니다. 서버 시작 전 반드시 실행해야 합니다.
3. **서비스 시작**
   - 테스트: `sudo replayshield serve`
   - systemd: `sudo systemctl enable --now replayshield`
   - 서비스가 시작되기 전에 2단계의 캐시 작업이 선행되어야 합니다.
4. **PAM 동작 확인**
   - SSH 접속을 시도하면 PAM 스크립트가 `http://127.0.0.1:4444/auth` 에 사용자명/암호를 전달하고, 응답이 `PASS`일 때만 인증을 계속 진행합니다.

## 프로젝트 구조

| 경로 | 설명 |
| --- | --- |
| `src/main/java` | ReplayShield 애플리케이션 코드 |
| `packaging/systemd/replayshield.service` | systemd 유닛 |
| `packaging/replayshield-pam.sh` | PAM helper 스크립트 |
| `packaging/replayshield.sh` | `/usr/bin/replayshield` 래퍼 |
| `packaging/build-deb.sh` | Debian 빌드 스크립트 |
| `packaging/debian` | Debian 메타데이터 |

## 라이선스

MIT License (`LICENSE` 참고).
