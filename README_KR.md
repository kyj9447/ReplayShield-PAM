# ReplayShield-PAM

[English README](README.md)

ReplayShield는 PAM(예: SSH) 인증 과정에서 최근에 사용된 암호를 거부하여 재사용 공격을 막아 주는 경량 HTTP 인증 서비스입니다.

사용자별 인증 전용 암호 풀과 사용 이력을 저장하고, 설정된 윈도우(`block_count`) 안에서 재사용된 암호를 자동으로 차단합니다.


## 주요 기능

- `replayshield init/manage/password/serve` CLI로 아래 기능 제공
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
   - `/etc/pam.d/sshd` 등에 다음 줄을 추가합니다.
     ```
     auth required pam_exec.so quiet expose_authtok /usr/lib/replayshield/replayshield-pam.sh
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

      tmpfs on /dev/shm **type tmpfs** (rw,nosuid,nodev,inode64)

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

## 라이선스

MIT License (`LICENSE` 참고).
