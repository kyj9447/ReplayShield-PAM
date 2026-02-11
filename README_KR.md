# ReplayShield-PAM

[English README](README.md)

ReplayShield는 PAM(예: SSH) 인증 과정에서 최근에 사용된 암호를 거부하여 재사용 공격을 막아 주는 경량 HTTP 인증 서비스입니다.

사용자별 인증 전용 암호 풀과 사용 이력을 저장하고, 설정된 윈도우(`block_count`) 안에서 재사용된 암호를 자동으로 차단합니다.


## 주요 기능

- `replayshield init/manage/password/serve/benchmark` CLI로 아래 기능 제공
  - `init` : 초기화
    - 실행시 프롬프트로 Admin 암호를 입력하면 해당 암호로 암호화된 DB 파일 생성. 재실행시 해당 과정 다시 진행하고 DB파일 덮어씌워 초기화.
  - `manage` : 사용자/암호 풀 관리
    - `Add new user` : 새 사용자, 비밀번호 추가
    - `Manage user` : 특정 사용자 관리
    - `Delete user` : 특정 사용자 삭제
    - `Change admin password` : 현재 Admin 암호 변경
    - `DB dump` : 전체 DB 출력
  - `password` : 관리자 키 캐싱
    - `replayshield serve`시 사용할 Admin 암호 캐싱 ( tmpfs에 저장 )
  - `serve` : 인증 서버 실행
    - `replayshield serve`에서 저장한 캐싱된 Admin 암호를 사용해 인증 서버 실행
  - `benchmark` : DB 성능 벤치마크
    - 실제 인증 플로우를 측정하고 반복별 복호화/암호화 시간을 분리 기록 (`--mode=actual|test`, `--warmup`, `--iterations`)

- 암호화된 SQLite DB: 디스크에는 항상 암호화된 상태로 저장되고 `/dev/shm` tmpfs에서만 복호화.
- `/auth` HTTP POST 엔드포인트가 `PASS`/`FAIL`을 반환하여 PAM 스크립트가 인증 결과로 활용.
- `pam_exec.so expose_authtok`와 연동되는 PAM 스크립트 제공(`/usr/lib/replayshield/replayshield-pam.sh`)

## 1. 설치

요구 사항: JDK 21

```bash
sudo dpkg -i replayshield_*.deb
```

## 2. 설정

1. **PAM 설정**
   - 아래 두 PAM 항목을 모두 추가합니다.
   - `/etc/pam.d/sshd` 등에 다음 auth 줄을 추가합니다.
     ```
     auth required pam_exec.so quiet expose_authtok /usr/lib/replayshield/replayshield-pam.sh
     ```
   - `/etc/pam.d/sshd`, `/etc/pam.d/login`에 다음 session 줄을 추가합니다.
     ```
     session optional pam_exec.so /usr/lib/replayshield/replayshield-login-notify.sh
     ```
   - `/etc/pam.d/sshd` 등에 다음 줄을 주석 처리합니다. (기본 Unix 암호는 사용하지 않습니다.)
      ```
      @include common-auth/account/session
      ```
   - Google OTP 등 다른 모듈을 추가하려면 ReplayShield 라인 앞뒤에 적절히 배치합니다.

2. **파일 시스템 확인**
   - `/dev/shm` 이 tmpfs인지 확인합니다.
      ```
      mount | grep /dev/shm
      ```
      예시 출력 :
      ```
      tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)
      ```

## 3. 실행

1. **초기화 & 관리**
   ```bash
   sudo replayshield init      # salt와 암호화 DB 생성 (재실행 시 전체 초기화)
   sudo replayshield manage    # 사용자/암호 풀 관리, block_count 조정 등 진행
   ```
2. **관리자 암호 캐시**
   ```bash
   sudo replayshield password
   ```
   - `/dev/shm/replayshield/admin.key` 에 관리자 암호를 RAM에 저장합니다.
3. **서비스 시작**
   - systemd: `sudo systemctl start replayshield`
   - 정상 실행시 캐싱된 Admin 암호를 삭제하므로, 서비스 재시작시 암호 캐싱을 다시 진행 후 서비스를 재시작해야합니다.

4. **PAM 동작 확인**
   - SSH 접속을 시도하면 PAM 스크립트가 `http://127.0.0.1:4444/auth` 에 사용자명/암호를 전달하고, 응답이 `PASS`일 때만 인증을 계속 진행합니다.

## 4. 제한사항 및 전제 조건

- **Java 버전 고정**: 실행/빌드 모두 Java 21 기준입니다.
- **운영체제 전제**: Linux 환경을 전제로 동작합니다 (`/dev/shm`, `/proc/mounts`, PAM, systemd 사용).
- **아키텍처/런타임 제약**: 빌드 산출물에는 SQLite 네이티브 라이브러리가 Linux x86_64(glibc)만 포함되며 ARM/aarch64, macOS, Windows, Alpine(musl) 환경은 지원하지 않습니다.
- **메모리 파일시스템 필수**: `/dev/shm` 이 반드시 tmpfs(메모리 기반)여야 하고 쓰기 가능해야 합니다.
- **root 권한 필수**: `replayshield` 모든 명령은 root(`sudo`)로 실행해야 합니다.
- **TTY(대화형 콘솔) 필요 명령**: `init`, `manage`, `password`는 콘솔 입력이 필요하므로 비대화형 환경에서 실행할 수 없습니다.
- **고정 경로 사용**: salt/암호화 DB/cache 파일 경로는 각각 `/etc/replayshield/salt.bin`, `/var/lib/replayshield/secure.db.enc`, `/dev/shm/replayshield/admin.key`로 고정되어 있습니다.
- **로컬 루프백 바인딩**: 인증 서버는 `127.0.0.1:4444`에만 바인딩됩니다.
- **PAM/도구 의존성**: `pam_exec.so expose_authtok` 기반 PAM 설정과 `curl`이 필요합니다.
- **서비스 시작 전제**: `serve` 실행 전 `replayshield password`로 admin key를 캐시해야 하며, 정상 시작 시 캐시 키는 삭제됩니다(재시작/재부팅 시 재캐시 필요).

## 라이선스

Apache License 2.0 (`LICENSE` 참고).  
소스/바이너리 형태로 자유롭게 사용·수정·배포할 수 있으나 다음 조건을 지켜야 합니다.
- 배포물에 Apache 2.0 라이선스 사본(및 NOTICE 파일이 있을 경우 함께)을 포함할 것
- 수정한 파일에는 변경 사항이 있음을 명시할 것
- 기존 저작권/특허/표시 문구를 그대로 유지할 것

소프트웨어는 “있는 그대로(AS IS)” 제공되며, 명시적·묵시적 보증이 없습니다.
