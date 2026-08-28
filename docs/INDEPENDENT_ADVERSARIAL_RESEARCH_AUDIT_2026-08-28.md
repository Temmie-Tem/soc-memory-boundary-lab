# 독립 adversarial research audit — 2026-08-28–29

## 작성·감사 메타데이터

- 대상: Samsung Galaxy A90 5G `SM-A908N`, Qualcomm `SM8150`
- 감사 시각: 2026-08-28 KST 시작, 2026-08-29 KST 최종화
- 주 작성자 및 최종 합성자: 현재 Codex Desktop task의 primary agent
- 독립 감사자:
  - `Jason` (`arch_security_audit`): SoC/memory-controller architect와 TrustZone/QHEE/XPU 관점
  - `Boyle` (`firmware_kernel_exploit_audit`): firmware reverse-engineering, kernel/driver, hardware-exploit 관점
  - `Laplace` (`dram_verification_blue_audit`): DRAM/Rowhammer, verification, skeptical blue-team 관점
- 현재 세션의 로컬 `turn_context`에 반복 기록된 요청 모델 ID: `gpt-daybreak-blue-latest`
- 현재 세션 및 세 독립 감사 task에 기록된 추론 강도: `max`
- 로컬 model cache의 표시명/설명: `Daybreak Blue`, “broad defensive cybersecurity work”용 frontier agentic coding model. OpenAI 공식 문서는 Daybreak Blue를 방어적 보안 작업용 safeguard가 적용된 flagship general-purpose model alias로 설명하고 `gpt-daybreak-blue-latest`와 `gpt-5.6-sol`의 관계를 모델 페이지에 열거한다. [OpenAI 공식 Daybreak Blue 모델 문서](https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest)
- 식별 한계: 위 값은 이 task가 요청·기록한 모델/effort를 확인한다. 개별 응답을 생성한 비공개 backend deployment나 checkpoint에 대한 암호학적 attestation은 아니다.
- 세션 ID: `01a048c9-9f97-7f22-b319-46a0d38130d4`; 세 reviewer도 각자의 session log에서 동일 model/effort가 확인되었다.
- 초안 후 hostile review: 세 reviewer가 담당 영역을 다시 읽어 제기한 P1/P2를 반영했으며, 수정본에 대해 세 명 모두 잔여 P0–P2 `PASS`를 확인했다. Reviewer들은 파일을 직접 수정하지 않았다.

## 범위, 기준점, 안전 경계

이번 감사는 기존 `CLASS C`, Route 1–4, P1/P2, `PROVED/REFUTED/UNKNOWN` 표기를 결론으로 상속하지 않았다. 먼저 retained raw와 exact binary/source를 다시 읽고, 독립 role pass를 끝낸 뒤에만 기존 문서 및 기존 감사 결과와 대조했다.

감사 기준 ref는 다음과 같다.

| ref | 감사한 기준점 | 관계와 사용법 |
|---|---|---|
| `main` | `746def0cfb7a14b9408945664544953937faadb2` | 현재 worktree. Experiment 014, V015/V016 통합 및 XBL/DCB 정적 계열의 기준 |
| `codex/config-cdt-integration` | 증거 감사 기준 `4ea9680c8f69f3a145abb75aa7a758e2ff5aeaf0`; 종료 시 tip `c45d8633539125dc1ac966605a0f02c5b2a6c203` | `main`의 descendant이며 V017–V029, V022R, V024와 기존 독립감사 `4ba9400` 포함. 감사 도중 다른 task가 `GOAL.md`만 추가 commit하여 기준점을 분리했다 |
| `research/xbl-config-cdt` | `99eb1dc50c9e6e1c4ab045dd76520aec2adb942b` | `247b0e1`에서 diverge한 별도 연구선. 원 V015–V019, Route-2 종료 주장과 독립적인 판단 이력 확인 |
| `backup/pre-rebase-20260826` | `3e8c7ca508fd188b98f63f0d806c69c07cb8fb0d` | `main`의 ancestor. 현 결론에만 존재하는 독립 증거는 찾지 못함 |
| `remotes/tmpmain` | `02b6f855a5a665cb10ee1ed94c3e19fe82ef1870` | `main`의 ancestor. 현 결론에만 존재하는 독립 증거는 찾지 못함 |

`codex/config-cdt-integration` worktree에는 감사 종료 시 물리주소 oracle 및 다음 실험 설계의 미커밋 파일들이 있었다. 이는 다른 작업의 진행 중 자료로 보존했고 수정·실행하지 않았으며, retained evidence로 승격하지 않았다. `research/xbl-config-cdt`의 등록 worktree path는 prunable 상태여서 Git object로만 읽었다.

핵심 근거의 재검증 위치는 다음과 같다.

| 주제 | retained/exact source |
|---|---|
| Experiment 014 low-bit timing | [014 timing manifest](../evidence/manifests/014-dram-conflict-timing-20260825-01.manifest.json), [timing analyzer](../tools/a90_dram_timing_analysis.py) |
| V015 condition별 invariance | [V015 manifest](../evidence/manifests/verification-015-runtime-invariance-20260826-01.manifest.json), [analyzer](../tools/a90_runtime_invariance_analysis.py) |
| V016 high-bit와 median/base 결함 | [V016 manifest](../evidence/manifests/verification-016-high-bit-relation-20260827-01.manifest.json), [probe](../tools/a90_region_probe_r.c), [analyzer](../tools/a90_high_bit_relation_analysis.py), [pair raw](../evidence/private/verification-016-high-bit-relation-20260827-01/pa25-27-heldout.jsonl) |
| V018 alias negative | [preliminary manifest](../evidence/private/verification-018-a90-20260827-02/preliminary-manifest-v2.json), [raw](../evidence/private/verification-018-a90-20260827-02/alias-marker.jsonl) |
| V019 deep suspend | [run-1 raw](../evidence/private/verification-019-suspend-permutation-20260827-01/suspend-permutation.jsonl), [run-2 raw](../evidence/private/verification-019-suspend-permutation-20260827-02/suspend-permutation.jsonl), branch manifests `8c3d1c5:...-01.manifest.json` 및 `1bc494e:...-02.manifest.json` |
| V022R high-bit 개선 | [raw](../evidence/private/verification-022r-pa28-live-20260827-01/pa28-identification.jsonl), branch manifest `a86a955:evidence/manifests/verification-022r-pa28-live-20260827-01.manifest.json` |
| V027–V029 independent recovery/OOS | [V028 raw](../evidence/private/verification-028-bank-triple-live-20260828-01/bank-triple.jsonl), [V029 raw](../evidence/private/verification-029-model-oos-live-20260828-01/model-oos.jsonl), prereg/result commits `3799238`/`829b1e9`, `c52f2f5`/`ca6ae02` |
| XPU policy/initializer | [009 policy manifest](../evidence/manifests/009-xpu-policy-inventory-20260825-01.manifest.json), [010 initializer manifest](../evidence/manifests/010-xpu-initializer-inventory-20260825-01.manifest.json), [013 SHRM boundary](../evidence/manifests/013-shrm-snapshot-boundary-20260825-01.manifest.json), [policy decoder](../tools/sm8150_xpu_policy_inventory.py), [initializer decoder](../tools/sm8150_xpu_initializer_inventory.py) |
| XBL/DCB bounded search | [034 manifest](../evidence/manifests/034-dcb-site35-jump-table-20260826-01.manifest.json), [Experiment matrix](EXPERIMENT_MATRIX.md) |
| exact firmware identity | [capture metadata](../evidence/private/004-live-firmware-readonly-20260825-01/capture-metadata.json), [AOP binary](../evidence/private/004-live-firmware-readonly-20260825-01/aop--sdd7.bin), [TZ binary](../evidence/private/004-live-firmware-readonly-20260825-01/tz--sdd5.bin) |
| exact kernel/config/symbols | [System.map](../evidence/private/007-kernel-remapper-readonly-20260825-02/System.map), [exact kernel QMP client](/home/temmie/dev/android-native-init-lab/workspace/private/work/public_a90_r3q/kernel_samsung_r3q-e1d271581eff/drivers/soc/qcom/qmp-debugfs-client.c), [DCC source](/home/temmie/dev/android-native-init-lab/workspace/private/work/public_a90_r3q/kernel_samsung_r3q-e1d271581eff/drivers/soc/qcom/dcc_v2.c), [debugcc source](/home/temmie/dev/android-native-init-lab/workspace/private/work/public_a90_r3q/kernel_samsung_r3q-e1d271581eff/drivers/clk/qcom/debugcc-sm8150.c) |
| prior branch audit cross-check | commit `4ba9400`, `docs/ADVERSARIAL_AUDIT_2026-08-28.md`; 이 보고서는 그 결론과 analyzer를 권위로 상속하지 않았고 DCC/XPU 과대해석을 별도로 수정함 |

이번 pass에서 수행하지 않은 것: `adb`, `fastboot`, A90P1/USB/device contact, direct MMIO/SMC, controller write, DCC 실행, debugfs write, protected-memory operation, firmware/partition 변경. 생성한 유일한 workspace 산출물은 이 보고서다.

이 보고서의 근거 등급은 다음처럼 읽는다.

- `DIRECT`: exact target에서 실제 측정한 retained raw
- `STATIC-EXACT`: SHA-256으로 결박된 exact target binary/source/DT의 정적 사실
- `INFERRED`: 직접 측정과 정적 사실을 연결한 구조적 추론
- `SUBSUMPTION`: 다른 실험이 대신 닫는다고 주장한 것
- `SEARCH-NEGATIVE`: 정해진 extractor/model에서 찾지 못한 것
- `NOT-EXECUTED`: 안전/연구 계약상 만들지 않은 상태
- `OBSERVER-BLIND`: 현재 관측기가 식별할 수 없는 것
- `HARDWARE-NONRETURN`: exact hardware access가 값을 반환하지 않고 watchdog/reset으로 끝난 것. 원인은 별도 문제다

---

## 1. 현재 Class C 논리의 재구성

현재 문서의 결론은 대체로 다음 사슬이다.

```text
normal-RAM timing에서 숨은 same-selection 관계 관측
  -> 완전 alias가 아니라 bank/interleave transform이라고 해석
  -> 알려진 remapper/controller direct aperture는 EL1에서 값을 반환하지 않음
  -> exact TZ/XPU 정적 정책도 접근 차단 해석을 지지
  -> XBL/DCB/firmware에서 관련 runtime writer를 찾지 못함
  -> reboot/suspend 등에서 관계 또는 내용 주소가 유지됨
  -> mutation, complete alias, protected effect가 없으므로 CLASS C (TRANSFORM ONLY)
```

첫 링크는 강하다. 중간의 “direct APSS path”와 “bounded static search”도 각각 정확한 범위에서는 유효하다. 그러나 이를 “모든 initiator/interface가 차단됨”, “runtime writer가 없음”, “full transform이 invariant”, “protection ordering이 안전함”으로 연결하는 링크는 증거보다 넓다.

### 1.1 low-bit same-selection transform

`CLAIM ->` 이 target의 normal RAM에는 PA13–23의 비자명한 3차원 same-selection/bank-kernel 관계가 있고, PA24를 포함한 별도 model-coordinate witness에서도 rank floor 3이 성립한다.

`EVIDENCE ->` `DIRECT`: Experiment 014의 16 MiB PA-bound CMA 구간 `0xf0400000..0xf13fffff`에서 네 held-out kernel vector의 p10 최솟값 536, 네 one-output-bit negative의 p90 최댓값 222, gap 314가 남았다. basis는 `0x9d2000`, `0xa74000`, `0x4e8000`이다. `codex/config-cdt-integration`의 V027은 같은 corpus를 독립 recovery model로 재구성했다. V028은 실행 전 commit `3799238`에서 두 triple을 고정한 뒤 모든 7개 비공집합 XOR을 측정하여 `rank(f) >= 3`을 방어했으며, 그 witness `{0x2000, 0x4000, 0x1000000}`에는 PA24가 포함된다. V029는 preregistration `c52f2f5` 뒤 PA13–23 범위에서 8/8 OOS를 얻었다.

`HIDDEN ASSUMPTION ->` timing conflict가 DRAM row-buffer의 동일 selector를 나타내고 LLCC/NoC/CPU noise가 같은 동치관계를 모방하지 않는다는 것. 또 recovered output basis를 channel/rank/BG/bank 의미론으로 부를 수 있다는 것.

`POSSIBLE COUNTEREXAMPLE ->` LLCC slice 또는 NoC arbitration이 동일한 GF(2) kernel을 만들거나, 관측된 세 출력이 bank/BG/rank 중 무엇인지 전혀 다를 수 있다. `B' = B xor H(R)`인 정상적이고 bijective한 bank hash도 모든 결과를 설명한다.

`CURRENT CONFIDENCE ->` **높음, 단 범위 한정**. “PA13–23 timing-equivalence kernel”과 “PA24를 포함한 model-coordinate rank floor 3”을 구분하면 둘 다 강하다. “complete DRAM map”, “security remapper”, “channel/rank/BG 의미”는 아직 아니다. V029의 8개 vector는 모두 `< 0x1000000`이므로 high-bit OOS가 아니다.

### 1.2 transform은 존재하지만 mutation은 증명되지 않음

`CLAIM ->` 관측된 transform은 존재하나 runtime mutation은 증명되지 않았다.

`EVIDENCE ->` `DIRECT`인 것은 고정 상태의 timing 관계다. V015는 여러 condition마다 별도 widest-gap threshold를 만들고 conflict label을 비교했다. 네 비교는 invariant였지만 `v2321-L762`에는 두 disagreement가 남아 canonical status가 `REPEAT_REQUIRED`이며, 별도 repeat의 surviving flip은 0이어도 이 status를 승격하지 않는다. V019는 같은 uninterrupted boot에서 별도 성공 acquisition 두 건을 얻었고, 각각 약 25.090초와 25.151초 deep suspend 뒤 4,194,304 tag가 `moved=0`이었다. 실제 transform register readback/write나 before/after exact physical-pair map은 없다.

`HIDDEN ASSUMPTION ->` conflict label/kernel 불변이 full coordinate transform 불변이고, 내용이 같은 offset에서 돌아온 것이 controller mapping 불변이라는 것.

`POSSIBLE COUNTEREXAMPLE ->` invertible output-basis permutation, affine constant, PPR row permutation, row/column-only 변화는 same-bank kernel을 보존한다. suspend resume는 저장값을 복원하지만 OPP/PASR/SSR은 suspend와 다른 AOP/remote control path로 dispatch될 수 있다. Exact QMP sender→PASR/frequency apply-handler link는 아직 미복구다.

`CURRENT CONFIDENCE ->` **mutation 미증명은 높음; immutability는 낮음/UNKNOWN**. 현재 증거는 “관측된 표본 label이 선택된 상태에서 안정적”까지만 지지한다.

### 1.3 알려진 controller/remapper aperture의 Normal-World 사용 불가

`CLAIM ->` 알려진 remapper aperture는 Normal World에서 사용할 수 없다.

`EVIDENCE ->` `HARDWARE-NONRETURN`: instance 0의 fixed address `0x09248080`에 대한 한 load는 값을 반환하지 않고 watchdog으로 끝났고 LOW/MID 계열에서 재현되었다. paired control은 같은 map/unmap 경로를 통과했지만 MMIO load는 0회였다. `/dev/mem` 계열 실패는 exact config의 `CONFIG_DEVMEM=n` 때문에 MMIO 도달 전 실패했다.

`HIDDEN ASSUMPTION ->` non-return의 원인이 XPU/access denial이고 clock/power/fabric/stage-2/instrument 결함이 아니며, 한 instance와 한 offset이 네 instance 및 모든 관련 block을 대표한다는 것.

`POSSIBLE COUNTEREXAMPLE ->` powered-off sub-aperture, external abort, QHEE stage-2 fault 또는 harness의 모든 MMIO load 실패도 같은 watchdog을 만든다. instance 1–3은 직접 자극하지 않았다. MCCC debug path나 AOP/DCC/remote master는 CPU direct load와 다른 initiator다.

`CURRENT CONFIDENCE ->` **“exact APSS direct-load harness에서 instance0가 비생산적”은 높음; “XPU가 거부”는 중간 이하; “Normal World의 모든 간접 사용 불가”는 낮음**.

### 1.4 XPU 정책이 aperture를 충분히 덮음

`CLAIM ->` known XPU policy가 remapper aperture를 충분히 덮고 HLOS/Normal World를 차단한다.

`EVIDENCE ->` `STATIC-EXACT`: exact TZ initializer에서 instance0 `0x09248080`은 `DC_NOC_BROADCAST_MPU`의 narrow region 11, `0x09248000..0x09249000`, raw read permission `0x80000000`, write 0에 걸린다. 동시에 더 넓은 MEMNOC/CNOC records도 있다. instance1–3의 `+0x8080`에는 이 narrow region이 없고 broad records만 관측된다.

`HIDDEN ASSUMPTION ->` project decoder가 bits 28–31의 client/security 의미를 정확히 이름 붙이고, overlapping MPUs 중 어떤 것이 APSS 또는 다른 master의 실제 path에 놓이는지 알며, boot-time records가 final live policy라는 것.

`POSSIBLE COUNTEREXAMPLE ->` `tools/sm8150_xpu_policy_inventory.py:424-427`은 region마다 broad client vector가 달라도 “MSA-class read-only; no standard VMID/HLOS”라는 문장을 하드코딩한다. `tools/sm8150_xpu_initializer_inventory.py:620-696`은 full client vector를 report/validation에서 버린다. broad regions에는 non-owner client write bits가 존재한다. 그 client가 APSS인지 remote master인지, actual path에서 어느 MPU가 우선하는지는 아직 모른다.

`CURRENT CONFIDENCE ->` **instance0 narrow raw-policy fact는 높음; HLOS 명명, all-master denial, 네 instance의 effective policy는 낮음/UNKNOWN**. 기존 branch 감사가 bit30을 곧바로 HLOS라고 확정한 것도 retained firmware만으로는 과한 이름 붙이기다.

### 1.4.1 Audit A가 제기한 XPU 반증과 retained EL2 fault의 후속 판정

이 subsection은 최초 세 독립 감사자의 hostile review가 끝난 뒤, Audit A `4ba9400:docs/ADVERSARIAL_AUDIT_2026-08-28.md` §2.2–2.3이 제기했으나 위 본문이 명시적으로 채점하지 않은 두 묶음을 Audit B의 주 작성자가 host-only로 다시 판정한 기록이다. 최초 reviewer 세 명의 판정으로 소급 귀속하지 않는다.

**A1 — `CONFIRMED`, 단 제시된 APSS/DDRSS 검증 집합에 한정.** Exact TZ `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`의 두 selector branch를 직접 다시 풀면 nearest-target record는 다음과 같다.

| live DT가 HLOS driver에 넘기는 page 또는 probe | nearest-target MPU raw `read_vmid` | raw `write_vmid` | VMID bit 3 술어 |
|---|---:|---:|---|
| `syscon@90b0000` | `0x40000000` | `0x00000000` | read/write 모두 `False` |
| `cpu-cpu-llcc-bwmon@90b6400` | `0x40000000` | `0x40000000` | read/write 모두 `False` |
| `llcc-pmu@90cc000` | `0x40000000` | `0x40000000` | read/write 모두 `False` |
| `cpu-llcc-ddr-bwmon@90cd000` | `0x40000000` | `0x40000000` | read/write 모두 `False` |
| `llcc@9200000` | `0xc0000000` | `0xc0000000` | read/write 모두 `False` |
| non-return probe `0x09248080` | `0x80000000` | `0x00000000` | read/write 모두 `False` |

[Exact probe boot](../evidence/private/007-inline-remapper-read-20260825-01/boot_linux_inline_remapper_read_v1.img) `6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed` 안의 두 DTB에는 다섯 node가 모두 있고 disabled 표기가 없다. [V023 retained log](../evidence/private/verification-023-last-kmsg-at-mid-20260827-01.last_kmsg.bin)에는 두 bwmon과 LLCC PMU가 등록된 사실도 남는다. 따라서 `hlos_present_in_read_mask`/`hlos_present_in_write_mask`, 즉 raw bit 3 존재 여부는 이 다섯 positive/reference page와 non-return page를 구별하지 못한다. 이 판정은 bit 30을 누구라고 이름 붙이는 주장과 독립적이다. 다만 전체 109 region에서 bit-3 함수가 상수라는 뜻은 아니며, 여기서 `판별력 없음`은 이 관련 접근 집합의 effective HLOS reach를 예측하는 용도에 한정한다.

**A2 — `CONFIRMED`.** 같은 exact TZ의 두 branch에서 `CNOC_AOSS_MPU` table ordinal 5는 `0x17c00000..0x18200000`, `read_vmid=write_vmid=0x00000000`이다. Raw record의 별도 `index` 필드는 6이므로 여기서 “region 5”는 table ordinal을 뜻한다. 그런데 V023 retained log에는 `msm_watchdog 17c10000.qcom,wdt: [pet_watchdog]`가 9.952084초부터 85.728094초까지 9회, 평균 약 9.472초 간격으로 기록된다. 대응 [watchdog source](/home/temmie/dev/android-native-init-lab/workspace/private/work/public_a90_r3q/kernel_samsung_r3q-e1d271581eff/drivers/soc/qcom/watchdog_v2.c)는 각 로그 전에 `WDT0_STS`를 read하고 `WDT0_RST`에 write한 뒤 `WDT0_BARK_TIME`과 `WDT0_BITE_TIME`을 read한다. 따라서 HLOS가 발행한 MMIO read/write가 이 정적 all-zero region 안에서 실제 완료되었다. 이는 static address containment를 모든 initiator에 적용되는 평면적 deny로 해석하는 것을 반증하며, XPU instance/path 또는 final runtime policy가 필수 변수임을 보인다. XPU 전체 부재를 증명하지는 않는다.

**B1 — `CONFIRMED`, 구조 인식까지.** V023 retained log에는 `log_addr:858df200 log_size:1e00 offset:6b4 wrap:0` 뒤 Samsung Upload parser가 `Data abort`, `Faulting Address`, `Instruction Executed`, `ESR_EL2`, `FAR_EL2`, `ELR_EL2`를 모두 `Found`한 기록이 있다. 같은 dump에서 `print_noc_info`, `print_xpu_info`, `print_smmu_info`는 모두 `tz log is encrypted or not parsed yet!`로 끝난다. `0x858df200`은 live DT의 `hyp_mem` `0x85700000..0x85d00000` 안이며, [exact HYP ELF](../evidence/private/004-live-firmware-readonly-20260825-01/hyp--sdd33.bin) `646f8fca08b0eff56b1d8415d81c3041a775c1871400dc57448cb5103405a8e1`의 file-backed string 영역이 아니라 RW load segment의 BSS 범위에 있다. 따라서 네 reporter 중 HYP fault-record 구조만 인식됐다는 사실은 확인된다. 그러나 `Found[...]`는 필드 위치 발견이지 값 해독이 아니며, ESR/FAR/ELR의 값과 fault timestamp는 이 retained file에 출력되지 않았다.

**B2 — `UNDECIDABLE`.** 이 레코드는 Route-2 거부 주체가 XPU가 아니라 QHEE stage-2일 수 있다는 직접 관련 증거이지만 어느 쪽인지 결정하지 않는다. XPU/fabric denial이 external abort로 EL2에 보고된 경우, stage-2 permission fault가 XPU보다 먼저 차단한 경우, probe와 무관하거나 부차적인 HYP abort가 ring에 남은 경우가 모두 현재 관측과 양립한다. ESR의 EC/ISS/DFSC, FAR/HPFAR/ELR 값과 exact probe address/instruction/time 결박이 없기 때문이다.

Provenance도 분리한다. `fdceab48dc267dd74ec6c70edbec6b51ee13dcd8532cf8b121c4fe93b425c66e`인 V023 dump의 실행 대상은 `6fe92825…` remapper가 아니라 `7ee6a41f3f55f6eea768a7fd7b66bf011b84e63fa523ee8a0430a50091b02116` SHRM read `0x0906566c`였다. 별도 V024에서는 `6fe92825…` remapper boot가 live attestation되었고, 그 [retained dump](../evidence/private/last-kmsg-final.last_kmsg.raw.bin) `ee0d2548e5ca6461a77b5b16287542b7d8112cd574ed0ba046b1011ad16b7c6c`에도 같은 HYP markers가 반복된다. 이는 remapper incident와의 관련성을 지지하지만 B2의 인과 판정을 올리지는 않는다.

따라서 Route-2의 현재 문장은 **“direct load non-return은 `CONFIRMED`; XPU 대 stage-2/QHEE 거부 주체는 `UNDECIDABLE`”**이다.

### 1.5 알려진 aperture 집합의 대표성

`CLAIM ->` 네 `qhs_llcc + 0x8080` remapper window와 기존 MC/MCCC 후보가 relevant aperture 집합을 충분히 대표한다.

`EVIDENCE ->` `STATIC-EXACT`: exact XBL에 네 `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080` window와 six-slot 36-bit region placement logic가 있다. selected 6 GiB topology도 정적으로 결박되었다.

`HIDDEN ASSUMPTION ->` timing bank hash와 system-PA region placement가 같은 register family이고, direct register address만 찾으면 모든 setter/consumer가 포착된다는 것.

`POSSIBLE COUNTEREXAMPLE ->` MC/MCCC, LLCC, AOP DDR manager, NoC target translation, die-internal PPR는 별도 block이다. DCC와 debugcc는 다른 bus initiator/driver path이며, SMC/mailbox/remote processor는 address가 아니라 proxy axis다.

`CURRENT CONFIDENCE ->` **region remapper의 존재/주소는 높음; 그것이 timing kernel의 owner이거나 complete relevant set이라는 주장은 낮음**.

### 1.6 complete DRAM coordinate alias 부재

`CLAIM ->` 서로 다른 PA가 같은 complete DRAM coordinate/storage를 가리키는 alias는 아직 없다.

`EVIDENCE ->` `DIRECT`: V018은 한 state에서 bits 6..27, 4 anchors × 2 trials, 총 176 candidate를 marker oracle로 시험했고 전부 `DISTINCT`; same-storage positive control은 실제로 fired했다. Experiment 014도 bank-equivalence만 관측했고 storage alias를 만들지 않았다.

`HIDDEN ASSUMPTION ->` 시험한 offset XOR가 실제 physical XOR를 대표하고, segment/state-dependent alias가 없으며, bits 28+와 다른 allocation/owner에도 일반화된다는 것.

`POSSIBLE COUNTEREXAMPLE ->` carveout base carry, PA28+, state-dependent remap, row-only/PPR remap, protected destination만 관여하는 alias는 이 corpus 밖이다.

`CURRENT CONFIDENCE ->` **exact V018 state와 tested offsets에서 simple alias 부재는 높음; global complete-coordinate injectivity는 UNKNOWN**. “현상 부재”와 “시험 범위 밖”을 분리해야 한다.

### 1.7 protection ordering

`CLAIM ->` 현재 증거로 protection check와 final transform의 순서를 충분히 추론할 수 있다.

`EVIDENCE ->` 실제 ordering receipt는 없다. timing kernel, XPU static region, direct-load non-return을 조합한 `INFERRED` 사슬뿐이다.

`HIDDEN ASSUMPTION ->` XPU/QHEE가 system PA에 먼저 판단하고, 그 뒤 non-injective transform이 final DRAM destination을 바꾼다는 위협모델 그림이 실제 block order라는 것.

`POSSIBLE COUNTEREXAMPLE ->` complete mapping이 injective하거나, 별도의 access check가 **system-PA→complete DRAM-coordinate transform 뒤** final coordinate에 적용되면 보안 primitive가 아니다. 일반적인 target-side XPU 사실은 SMMU/VMIDMT 뒤 system-bus address 검사를 뜻할 수 있을 뿐 MC bank/row transform 뒤 검사를 증명하지 않는다.

`CURRENT CONFIDENCE ->` **낮음/UNKNOWN**. 현재 결과는 ordering을 식별하지 않는다.

### 1.8 deep suspend의 다른 transition subsumption

`CLAIM ->` deep suspend가 더 큰 물리 perturbation이므로 OPP/retraining/modem SSR/remote crash 등 더 작은 transition을 subsume한다.

`EVIDENCE ->` `DIRECT`: 같은 uninterrupted boot의 별도 acquisition 두 건에서 약 25.090초와 25.151초 suspend가 성공했고 각각 `moved=0`이었다. `SUBSUMPTION`: 이를 다른 firmware path에 일반화한 문서 주장.

`HIDDEN ASSUMPTION ->` perturbation 크기의 순서가 실행 code-path 집합의 포함관계와 같다는 것.

`POSSIBLE COUNTEREXAMPLE ->` suspend는 self-refresh와 saved-state restore만 거치지만 OPP/PASR는 exact AOP에서 확인된 `DDR_MGR`, `RailChng`, frequency/PASR vocabulary·partial parser와 관련된 별도 control path를 사용할 수 있다. 그 exact dispatch는 아직 가설이다. Modem SSR도 remote master/NoC path만 다시 초기화할 수 있다.

`CURRENT CONFIDENCE ->` **deep-suspend content-address stability는 높음; 다른 transition subsumption은 기각**.

### 1.9 DCB/XBL 경로 closure

`CLAIM ->` DCB/XBL 경로는 실질적으로 닫혔다.

`EVIDENCE ->` 두 서로 다른 명제를 분리해야 한다. (a) exact `xbl_config` replacement/boot route는 MBN/RSA/certificate와 actual failure position으로 강하게 닫힌다. (b) XBL/DCB runtime/global writer absence는 selected sites, aligned literals, 제한된 AArch64 forms와 bounded CFG의 `SEARCH-NEGATIVE`다. Experiment 034 자체도 `writer_absence=UNKNOWN`, `writer_absence_claim=false`다.

`HIDDEN ASSUMPTION ->` 서명된 이미지 교체 불가가 existing signed code의 runtime writer 부재를 뜻하고, 71 qualified sites/인식된 instruction set이 모든 indirect consumer를 대표한다는 것.

`POSSIBLE COUNTEREXAMPLE ->` computed pointer, indirect `BLR/BR`, unmodelled copy primitive, 다른 DCB section 또는 runtime alias 하나가 MC/MCCC/DDRSS destination으로 이어질 수 있다. AOP의 실제 computed-pointer store는 literal-first global absence가 왜 성립하지 않는지 보여주는 실물 반례다.

`CURRENT CONFIDENCE ->` **unsigned/replaced boot route closure는 높음; bounded XBL model 내부 negative는 높음; global writer absence는 낮음/UNKNOWN**.

### 1.10 조사한 firmware path의 runtime 대표성

`CLAIM ->` XBL/DCB/TZ/SHRM 검색이 실제 runtime writer/control path를 충분히 대표한다.

`EVIDENCE ->` 기존 정적 검색은 exact image를 잘 결박하지만 scope가 제한되어 있다. 이번 재분석에서 exact AOP callback `0x0b009030`이 runtime/computed base에 여러 DDR-aux register store를 수행하고, exact AOP가 `DDR_MGR`, `ddr_freq`, `perfmode`, `pasr`, `addr_hi/addr_lo`, `refresh`를 포함함을 확인했다. exact kernel에는 `CONFIG_QMP_DEBUGFS_CLIENT=y`, `CONFIG_QCOM_AOP_DDR_MESSAGING=y`와 generic AOP mailbox client code가 있다. exact TZ에는 contiguous plausible SMC dispatch record가 152개이며 기존 주요 inventory는 소수 record만 의미 복구했다.

`HIDDEN ASSUMPTION ->` boot firmware가 runtime owner를 대표하고, aligned literal/local dataflow가 computed base/mailbox service를 포착하며, direct callsite만으로 indirect/future path가 닫힌다는 것.

`POSSIBLE COUNTEREXAMPLE ->` AOP, HYP/devcfg indirect tables, ABL SMEM handoff, SHRM helper direction 1, remote processor deputy, generic QMP debugfs client가 별도 path를 만든다.

`CURRENT CONFIDENCE ->` **“충분히 대표한다”는 주장은 기각**. 새 path들은 mutation/bypass 증거가 아니지만 기존 global closure를 깨뜨린다.

### 1.11 `Class C` taxonomy 자체

`CLAIM ->` `CLASS C (TRANSFORM ONLY)`가 현상을 올바르게 분해한다.

`EVIDENCE ->` label은 bank mapping, storage alias, mutation, reachability, protection ordering, protected effect를 한 단계에 묶는다. 실제 증거는 이 축마다 다르다.

`HIDDEN ASSUMPTION ->` “transform”이 곧 security-relevant remap이고, no-alias/no-mutation이 동일 ordinal class에서 표현 가능하다는 것.

`POSSIBLE COUNTEREXAMPLE ->` 정상적 bijective bank hash는 `transform`이지만 보안 alias가 아니다. 반대로 alias가 없어도 bank mapping은 timing/Rowhammer의 fault-enabler가 될 수 있다. AOP PASR는 mapping mutation 없이 integrity/availability surface다.

`CURRENT CONFIDENCE ->` **taxonomy 수정 필요**. 현재 지지되는 것은 `C-MAP`이며 `C-ALIAS`, `C-MUTATION`, `C-REACH`, `C-ORDER`, `C-FAULT-ENABLER`는 별도 축이어야 한다.

---

## 2. 가장 약한 전제 10개 이내

아래 순서는 결론을 뒤집을 가능성과 현재 증거의 취약성을 함께 반영한다.

1. **V016을 PA25–27의 물리 high-bit 7/7 검증으로 보는 전제.** Probe는 32개 delta를 정렬한 뒤 `deltas[used/2]`, 즉 17번째 upper median을 쓴다. threshold 299에서 `0x6084000`과 `0xc180000`은 정확히 16/32만 `>299`; lower/upper 중앙값은 각각 226/475와 223/437이다. lower statistic으로 재구성하면 widest gap은 226→487, threshold 356, agreement 5/7이다. analyzer는 observed split/match/heldout를 `EXPECTED_*`로 하드코딩하고 preregistration은 retained되지 않았다.

2. **allocation offset XOR를 physical PA XOR로 보는 전제.** V016의 256 MiB allocation이 320 MiB camera carveout의 어디에 놓였는지 모르며 pagemap은 BLIND다. Probe의 `(a, a xor d)`는 실제로 `(B+a) xor (B+(a xor d))`이므로 base carry가 nominal high bit를 섞는다. V022R은 full-pool allocation과 carry rejection으로 개선했지만 출력 PA도 observed PFN이 아니라 declared base 계산이다.

3. **non-returning load를 XPU refusal로 인과 해석하는 전제.** paired control은 zero-load이므로 “MMIO load가 성공할 수 있다”는 positive control이 아니다. NoC/XPU/SMMU syndrome이나 live policy readback도 없다.

4. **raw XPU permission word를 HLOS/all-master denial로 정확히 번역했다는 전제.** broad client vectors가 formatter에서 소실되고, 설명문이 모든 region에 하드코딩된다. overlapping MPU의 path/precedence, bits 28–31의 exact actor, final live policy가 없다.

5. **네 `+0x8080` 주소와 APSS direct load가 모든 relevant interface를 대표한다는 전제.** AOP mailbox, DCC, debugcc/MCCC, SMC, DMA/SMMU, remote processor는 다른 proxy/initiator axis다.

6. **V015의 일부 label stability를 full transform invariance로 보는 전제.** condition별 threshold는 scale drift에는 강하지만 invertible basis change, affine relabel, row permutation, PPR에 blind하다. 네 비교는 invariant이나 `v2321-L762`의 두 disagreement와 `REPEAT_REQUIRED`가 남고 repeat도 이를 승격하지 않는다. 일부 transition provenance도 operator report/UNKNOWN이다.

7. **V019 deep suspend가 OPP/PASR/SSR/crash path를 subsume한다는 전제.** 같은 boot의 두 별도 acquisition에서 얻은 content-tag 안정성도 다른 firmware handler의 실행을 증명하지 않는다.

8. **bounded DCB/XBL model을 global writer census로 보는 전제.** known false-negative와 sparse model coverage가 있었고, 현재 manifest도 global absence claim을 금지한다. AOP computed-pointer writer는 search-space anchoring의 실제 반례다.

9. **V029 8/8을 “whole modelled range” OOS로 보는 전제.** 여덟 vector가 모두 PA13–23만 사용하여 PA24–28, V016, V022R을 독립 검증하지 않는다. 8/8 low-bit OOS로만 유지해야 한다.

10. **`transform observed + direct access non-return + no complete alias`로 protection ordering까지 추론할 수 있다는 전제.** injective completion과 non-injective completion, check-before와 check-after가 모두 현재 관측과 양립한다.

---

## 3. 과거 판단 오류와 현재 남아 있는 동일 패턴

| 과거 뒤집힌 판단 | failure signature | 현재 살아 있는 같은 패턴 |
|---|---|---|
| PA28은 512 MiB allocation이 필요 | arithmetic/search-space anchoring; “bit n”을 단순 span 요구량으로 환산 | V016/V022R에서 allocation offset과 physical XOR를 동일시 |
| heap ceiling은 256 MiB | 요청 크기를 allocator 능력으로 오해 | 한 성공 allocation의 base/contiguity를 full extent identity로 승격 |
| physical base는 UNKNOWN이나 DT에 이미 존재 | not-looked-for → not-there | SMC registry, AOP mailbox, ABL DDR-info handoff, XPU client vector의 불완전 추출 |
| “literature adds nothing” | 특정 음성 결과를 전체 source class에 일반화 | remapper-size 문헌 음성을 PPR/AOP/XPU/SMEM observer까지 확대할 위험 |
| tautological verifier가 독립 검증처럼 보임 | expected output를 코드에 재기입; observer가 model 오류를 거부하지 못함 | V016 `EXPECTED_*`; V029 범위 과대표현; XPU fixed narrative formatter |
| debug-level/TWRP transition 순서가 예상과 달랐음 | state/provenance mismatch | V015의 일부 condition, final overlay/live binding, suspend→다른 path subsumption |
| 5/1,726 XPU record 추출을 protection absence처럼 해석할 수 있었음 | incomplete extraction scope | 152 SMC record 중 일부만 의미 복구; DCB selected-site/global 혼동 |
| literal/recognized-form search의 0 hit | tool/model limitation을 hardware absence로 변환 | computed-pointer AOP writes, indirect BLR/BR, SHRM direction-1 future caller |
| direct MMIO failure | observer가 한번도 positive하지 않았는데 target denial로 일반화 | zero-load control을 MMIO positive control로 취급, fault mechanism 미분류 |
| prior branch audit `4ba9400`의 DCC “read-only highest-value probe” 및 bit30=HLOS 확정 | 새 반례를 찾은 뒤 반대 방향으로 과대승격 | exact DCC에는 write descriptor와 programming side effect가 있고, raw client bit의 actor naming은 아직 미완성 |

공통 원인은 네 가지다. 첫째, **address 범위와 physical provenance의 혼동**. 둘째, **observer의 식별력보다 claim이 넓음**. 셋째, **한 code path나 initiator를 전체 topology로 확장**. 넷째, **`not observed`를 `does not exist`로 바꾸는 문장 승격**이다. 과거 오류를 개별 수정으로만 처리하면 같은 signature가 다음 extractor에 반복된다.

---

## 4. 현재 탐색의 구조적 blind spot

### 4.1 한 축만 촘촘하고 나머지 축은 성기다

기존 연구는 “주소 A를 APSS/EL1이 직접 읽을 수 있는가”를 깊게 파고들었다. 그러나 실제 표면은 적어도 다음 곱공간이다.

```text
initiator × proxy/interface × system state × transform kind × protection stage
```

| 축 | 현재 강한 부분 | blind spot |
|---|---|---|
| address | 네 remapper window, 일부 MC/MCCC, XPU range inventory | undiscovered controller family, die-internal mapping |
| initiator | APSS/EL1 fixed load 한 instance | AOP, DCC, DMA/SMMU, modem/DSP, secure processor |
| proxy/interface | custom ioremap, boot replacement | SMC 전체, mailbox/QMP, RPMh, debugfs/sysfs, remote request, diagnostics |
| state | LOW/MID, warm/cold 일부, 같은 boot의 deep-suspend acquisition 두 건 | OPP, PASR, SSR, recovery→system, crash/upload, early handoff, retrain |
| transform | low-bit timing kernel | channel/rank/BG 의미, row/column, PPR/ECC, LLCC/NoC, full injectivity |
| protection stage | static region data | master tag, overlap precedence, final live policy, pre/post-transform ordering |

### 4.2 timing observer의 의미론적 blind spot

현재 observer는 “같은 selection class인가”에는 강하지만 output label을 모른다. channel, rank, BG, bank를 분리하지 못하고 row/column/PPR/ECC를 보지 못한다. PA9/10의 upward class departure가 **독립 channel selector를 증명한다는 추론**은 saturation으로 반박됐지만, PA9/10이 channel 선택에 jointly 기여할 가능성은 UNKNOWN이다. 이 구분은 observer output을 너무 빨리 이름 붙이면 안 되는 이유를 보여준다.

### 4.3 physical-address provenance가 high-bit 결론보다 약하다

16 MiB CMA의 PA pin은 강하지만 큰 camera heap 경로는 declared region/base, allocator behavior와 offset arithmetic을 조합한다. exact PFN/SG observer가 없으면 high-bit model이 allocator carry artifact인지 구분하기 어렵다.

### 4.4 final live policy와 fault cause가 없다

static TZ initializer는 무엇을 설정하려는지 보여주지만 현재 boot의 실제 MPU/XPU register, master tag, overlap precedence를 보여주지 않는다. direct-load watchdog 뒤 retained log에는 hyp data-abort 관련 흔적이 있으나 ESR/FAR/ELR과 exact probe의 인과 결박이 없다. “XPU refusal”과 “QHEE stage-2 abort”는 전혀 다른 finding이다.

### 4.5 static search completeness를 정량화하지 않는다

XBL/DCB analyzers는 모델 안의 accounting은 엄격하지만 모델 밖의 instruction, indirect target, runtime alias, computed pointer를 global denominator로 만들지 못한다. AOP callback의 computed stores와 152-record SMC table은 “exact image를 썼다”와 “complete path를 복구했다”가 다름을 보여준다.

### 4.6 관측기 자체의 독립 검증이 부족하다

Experiment 014 original analyzer는 recovered basis와 expected output을 hardcode한 regression replay다. V027/V028이 이를 일부 보완했지만 high-bit는 독립 blind OOS가 없다. XPU formatter는 raw vector를 소실하고, prior SMC audit tool은 CLI input 일부를 hardcoded private path로 다시 읽는 재현성 결함이 있다.

### 4.7 branch별 사실이 한 상태처럼 읽힌다

`main`, diverged `research/xbl-config-cdt`, descendant `codex/config-cdt-integration`은 같은 experiment 번호의 서로 다른 세대와 claim 범위를 담는다. 예를 들어 V016 원결론, V022R의 개선, V029의 OOS는 한 ref에 동시에 있지 않다. branch/commit qualifier 없이 “현재 증거”라고 쓰면 시간·provenance mismatch가 발생한다.

### 4.8 crash/upload가 observer로 충분히 활용되지 않았다

Samsung Upload/SHRM은 post-reset snapshot을 이미 제공했다. 이는 runtime primitive가 아니지만 fatal probe의 fault cause, HYP/XPU/NoC syndrome, final policy 또는 DCC state를 비파괴적으로 복원할 수 있는 observer 후보가 될 수 있다. 현재는 set-0 MC snapshot과 일부 문자열 수준에 머문다.

---

## 5. 기존 taxonomy 밖에서 새로 만든 attack/control-surface map

기존 route 번호를 먼저 적용하지 않고 transaction과 control의 실제 방향으로 다시 그리면 다음과 같다.

```text
APSS/EL1 ─┬─ stage-2/QHEE ─┬─ NoC/XPU ─ LLCC ─ DDRSS/remapper ─ MC ─ DRAM die
          │                └─ SMMU/DMA master ────────────────────┘
          ├─ SMC/SCM ─ EL3/TZ proxy ─────────────────────────────┤
          ├─ debugfs/sysfs ─ kernel driver ─ DCC/debugcc ────────┤
          └─ mailbox/RPMh ─ AOP DDR manager ─────────────────────┤

modem/DSP/remote processor ─ VMIDMT/SID/NoC path ────────────────┘
XBL/xbl_config/ABL/devcfg/TZ/HYP ─ boot-time tables/policy ──────┘
Samsung crash/upload ─ post-reset observer of several layers
```

### 5.1 계층·initiator·interface별 지도

| 계층/주체 | direct 또는 proxy interface | 현재 exact-target 근거 | 독립 판정 |
|---|---|---|---|
| CPU/EL1 | fixed `ioremap` load | instance0 `0x09248080` non-return; map/unmap zero-load control만 성공 | exact harness의 bounded negative; 원인 UNKNOWN |
| EL2/QHEE | stage-2, HYP tables/log | retained upload log가 data-abort/FAR/ESR/ELR 문자열을 찾았고 devcfg에는 hyp uncached ranges/SMMU AC가 있음 | direct refusal의 대체 원인 및 remap/policy layer로 OPEN |
| EL3/TZ | SMC/SCM proxy | exact TZ에 152 contiguous plausible dispatch records. `SCM_IO_READ/WRITE`는 동일 81-entry allowlist 사용 | on-disk default table은 known DDRSS를 deny; table은 RW segment이고 runtime mutation/writer가 UNKNOWN. 나머지 service도 OPEN |
| TrustZone/XPU | initializer/policy | 109 region inventory, instance0 narrow policy, broad overlapping policies | raw fact는 강함; actor/path/final policy UNKNOWN |
| SMMU/DMA | IOMMU mapping, DMA master | exact config와 devcfg가 SMMU access control을 지지; initiator별 census 없음 | deputy/alternate-master surface OPEN |
| NoC/MEMNOC/GEM_NOC | target routing, VMIDMT/SID | Qualcomm 구조와 exact XPU records에서 initiator/path 구분 가능성이 큼 | protection topology와 overlap precedence UNKNOWN |
| LLCC | HLOS driver, slice/way/config, timing 앞단 | exact kernel과 DT에 LLCC driver/PMU/BW monitor; HLOS가 일부 LLCC state를 프로그램 | timing confounder 및 별도 transform; security remap 연결 없음 |
| DDRSS/remapper | four `qhs_llcc +0x8080` | exact XBL six-slot 36-bit placement logic | system-PA region remapper로 강함; bank-hash owner 여부 UNKNOWN |
| MC/MCCC | controller regs, debug clock path | exact DT `syscon@90b0000`; `debugcc-sm8150`은 MCCC `+0x50` period read를 시도하고 parent-selection 과정은 GCC/bus-vote state를 바꿀 수 있음 | recursive MCCC mux access는 regmap range error 가능; observer 성공도 pure-read-only도 보장되지 않음 |
| DRAM die | bank hash, row map, PPR/ECC/TRR | exact part/MR/PPR state 없음 | 가장 downstream인 별도 transform/fault surface OPEN |
| AOP/RPMh | mailbox/QMP, DDR manager, PASR/frequency | exact AOP vocabulary/partial parser·handler code와 computed-register stores; exact kernel에 generic QMP debugfs client와 AOP DDR messaging compiled | 새로운 indirect DDR-control **candidate surface**. sender→exact apply-handler dispatch, live binding/acceptance/effect는 UNKNOWN |
| modem/DSP/remote | SSR, shared memory, QMI, bus master | exact kernel에 legacy PIL/SSR/memshare/QMI 계열 존재; firmware capture set은 불완전 | “subsystem route 없음”을 말할 수 없음 |
| XBL/xbl_config | DCB/topology/remapper init | exact image 및 긴 bounded dataflow chain | signed replacement는 CLOSED; global existing-code writer는 UNKNOWN |
| ABL | SMEM DDR info → final DT | exact LinuxLoader strings에 `ddr_device_rank_ch%d`, `ddr_device_hbb_ch%d_rank%d`, DDR Info protocol | high-value read-only topology observer 후보 |
| devcfg/TZ/HYP | policy/uncached/remap init | `/ac/xpu`, `/ac/smmu`, `hyp_uncached_ranges`, SMMU AC enabled | boot policy의 두 번째 data source; full consumer dataflow 미복구 |
| Samsung upload/crash | SHRM, HYP/XPU/NoC log export | set-0 MC snapshot 및 post-reset diagnostic evidence | attacker primitive가 아니라 observer; causality recovery에 유용 |
| DCC | DT microprogram, SRAM/config regs, bus initiator | 두 embedded base DTB의 250 descriptors는 204 READ + 46 WRITE; retained log에 DCC entries | **read-only probe가 아님**. static design만 허용할 surface |

### 5.2 transform 종류별 지도

| transform/control | 설정 주체 후보 | 설정 시점/저장소 | reader/consumer | runtime mutation | protection 전후 |
|---|---|---|---|---|---|
| channel selection/interleave | XBL/DCB, DDRSS/MC | boot table/register | MC/NoC | UNKNOWN | UNKNOWN |
| rank selection/topology | XBL/DCB, ABL/SMEM DDR info | boot/SMEM/final DT | MC, kernel topology consumer | 보통 boot-fixed로 추정하나 미측정 | UNKNOWN |
| bank/BG XOR | MC/DDRSS 또는 die | boot register 또는 hardwired logic | DRAM scheduler/die | UNKNOWN | timing만으로 불명 |
| row mapping | MC 또는 die | register/fuse/repair table | DRAM die | PPR/retraining 경로 가능 | 가장 downstream일 가능성, exact 불명 |
| column/burst mapping | MC/die | controller/MR | DRAM | UNKNOWN | UNKNOWN |
| system-PA region remap | XBL `qhs_llcc +0x8080` family | boot-initialized register | NoC/DDRSS | writeability/lock UNKNOWN | XPU/QHEE와 순서 UNKNOWN |
| LLCC slice/cache transform | HLOS LLCC driver + hardware | boot/runtime LLCC config | cache/NoC | 일부 runtime programmable | DDR protection보다 upstream 가능, exact 불명 |
| NoC target translation | NoC fabric/config | boot/runtime QoS/config | target decoder | UNKNOWN | XPU 위치에 따라 달라짐 |
| SMMU/IOMMU remap | HLOS/HYP/TZ | runtime page table/context bank | DMA initiator | runtime 가능 | XPU 전/후 topology UNKNOWN |
| ECC redirection | MC/die | boot/fuse/runtime RAS | MC/die | repair policy에 따라 가능 | downstream |
| PPR/spare row | MC가 MRS로 명령, die가 저장 | runtime/irreversible fuse 가능 | DRAM die | soft/hard PPR에 따라 가능 | 완전 downstream |
| OPP/training/PASR/refresh | AOP DDR manager | runtime AOP state/register | MC/DDRSS/die | 설계상 runtime | mapping과 별개 integrity surface일 수 있음 |
| crash/debug/dump-dependent config | Samsung kernel/boot chain/TZ/HYP | reboot/handoff | upload, HYP, XPU | state-specific | UNKNOWN |

이 지도에서 새로 중요한 점은 세 가지다. 첫째, **direct aperture와 proxy는 별개**다. 둘째, **bank mapping과 refresh/PASR integrity는 별개**다. 셋째, **owner/configurator와 transaction accessor는 별개**다.

### 5.3 exact-target에서 새로 분리된 interface

1. **TZ SCM IO proxy — bounded static default-deny evidence.** Exact TZ의 read handler `0x1c03e37c`, write handler `0x1c03e2e0`은 같은 81-entry u32 allowlist `0x1c111238`을 순회한다. On-disk table에는 `0x09000000..0x09800000` 항목이 없어 네 remapper와 known MCCC/MC target이 기본 허용되지 않는다. 그러나 table은 RW PT_LOAD 안에 있고 handler가 runtime memory에서 읽으므로 final value, table writer와 mutation 부재는 UNKNOWN이다. 따라서 이는 runtime closure도 “SCM 전체” closure도 아니다.

2. **AOP mailbox/QMP — 새 control candidate surface.** Exact kernel image는 `qmp_msg_probe`/`aop_msg_write`와 `CONFIG_QMP_DEBUGFS_CLIENT=y`를 포함하고, embedded DT에는 `qcom,debugfs-qmp-client` string이 있다. Source는 최대 96-byte user message를 별도 class allowlist 없이 mailbox로 전달한다. Exact AOP에는 DDR/PASR/frequency vocabulary, partial parser·handler code와 별도의 computed-register callback이 있다. 그러나 generic sender가 그 exact parser/apply handler로 dispatch된다는 CFG link, final overlay binding, debugfs mount/SELinux, message acceptance와 protected-range effect는 아직 관측되지 않았다.

3. **DCC — 새 initiator이나 안전한 read observer가 아님.** Runtime-selected base DTB를 포함한 두 base DTB에 250개 four-cell descriptor가 있고 204 read, 46 write다. 46 write target은 `0x06a0e01c` 42회 및 `0x06a0e00c`, `0x06a0e014`, `0x06a0e008`, `0x090c80f8` 각 1회다. DCC driver는 SRAM/config MMIO를 쓰고 bus transaction을 실행한다. 그러므로 새로운 live DCC experiment는 이번 first-pass 금지 범위다.

4. **debugcc/MCCC — pure read-only를 보장할 수 없음.** `clk_measure`가 0444여도 parent-selection 과정은 GCC/다른 debug mux와 bus vote state를 바꿀 수 있다. 반면 exact MCCC regmap 크기는 `0x1000`인데 recursive mux offsets는 `0x62000/4/8`이므로 그 MCCC-side accesses는 range error가 날 수 있고 `clk-debug.c`가 오류를 무시한다. 따라서 MCCC `+0x50` read 성공과 recursive MCCC write 모두 증명되지 않았으며, arbitrary remapper access도 아니다.

5. **SHRM direction-1 — bounded static open.** Exact Xtensa helper `0x2d8dc`는 `(base_page << 12) + (offset_token << 2)`로 MMIO 주소를 만들고 direction 0은 MMIO→snapshot, direction 1은 staged word→MMIO store를 수행한다. 두 direct callsite는 direction 0이지만 indirect/future/other callers는 전역적으로 닫히지 않았다.

---

## 6. 외부 공개자료에서 새로 발견한 것

외부 자료는 exact A90 근거를 대신하지 않는다. 아래에서 `PRIMARY`는 vendor source/patent/paper/연구자 원문, `SECONDARY`는 요약, `INFERRED`는 다른 세대/IP에서 exact target으로의 제한적 교차추론이다.

| 발견 | source class, 버전/날짜 | 이번 감사에 주는 정보 | exact A90에 대한 한계 |
|---|---|---|---|
| XPU/VMIDMT는 initiator attribute와 target policy의 교집합이며 topology/path가 중요 | `PRIMARY`, Qualcomm *An Introduction to Access Control on Qualcomm Snapdragon Platforms*, 2020, 2026-08-28 조회. [PDF](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/an-introduction-to-access-control-on-qualcomm-snapdragon-platforms.pdf) | “address range 하나가 모든 initiator를 동일하게 막는다”는 가정을 경계하게 함 | exact SM8150 route/bit naming/final policy는 문서로 증명되지 않음 |
| Qualcomm bank mapping은 row/rank와 XOR할 수 있고 mode별 mapping이 달라질 수 있음 | `PRIMARY`, Qualcomm WO2021086540A1/US20210133100A1, priority 2019-10-30, publication 2021-05-06. [patent](https://patents.google.com/patent/WO2021086540A1/en) | 정상적 `B'=B xor H(R)` bijection 및 mode-dependent mapping이라는 downgrade/transition 반례 제공 | 특허 embodiment가 SM8150 A90 구현이라는 증거는 아님 (`INFERRED`) |
| Qualcomm downstream에는 HLOS→AOP raw QMP debugfs client가 존재 | `PRIMARY`, Android downstream 4.14 source, 2017–2018 copyright, 2026-08-28 조회. [qmp-debugfs-client.c](https://android.googlesource.com/kernel/msm/%2B/refs/heads/android-msm-coral-4.14-android10/drivers/soc/qcom/qmp-debugfs-client.c) | exact local source/System.map/config와 맞물려 indirect mailbox surface를 구체화 | exact final DT binding와 policy/effect는 live UNKNOWN |
| AOP DDR fixed/perf/PASR message ABI가 공개 source에도 존재 | `PRIMARY`, Android downstream 4.14 source. [AOP DDR messaging](https://android.googlesource.com/kernel/msm/+/refs/heads/android-msm-sunfish-4.14-android10-d4/drivers/soc/qcom/aop_ddr_msgs.c), [AOP DDRSS commands](https://android.googlesource.com/kernel/msm/+/refs/heads/android-msm-sunfish-4.14-android10-d4/drivers/soc/qcom/aop_ddrss_cmds.c), [mem-offline PASR](https://android.googlesource.com/kernel/msm/%2B/92ee988e8a68099fff565978f674f09e0e301b47%5E%21/) | suspend와 OPP/PASR가 다른 code path라는 직접적인 설계 반례 | local exact config에서는 dedicated DDRSS command와 mem-offline 경로 일부가 disabled; generic QMP path는 별도 |
| DCC는 read-only logger가 아니라 read/write/RMW microprogram engine | `PRIMARY`, Qualcomm downstream DCC v2, commit `33b671f`, 2019-06-04. [source](https://android.googlesource.com/kernel/msm/%2B/33b671f607d2e7fe630428dca64ca33cf6864c73/drivers/soc/qcom/dcc_v2.c); `PRIMARY` patch posting, Qualcomm engineer, 2022-11-16. [LKML](https://lkml.org/lkml/2022/11/16/578) | prior “safe read-only DCC” 제안을 반박하고 별도 bus initiator로 분류 | exact target descriptor/binding은 local DT/log로 따로 확인해야 함 |
| SM8150 debugcc는 MCCC period observer와 parent-selection machinery를 가짐 | `PRIMARY`, Android downstream snapshot, 2018-09-06. [debugcc-sm8150.c](https://android.googlesource.com/kernel/msm/%2B/6a21ebdd1776b264340649ecd6c439ce1f001bda/drivers/clk/qcom/debugcc-sm8150.c) | MCCC indirect observer 후보와 potential measurement side effect를 동시에 드러냄 | exact regmap range 때문에 recursive MCCC access는 실패할 수 있고 arbitrary register R/W나 transform ownership을 뜻하지 않음 |
| SCM IO read/write는 vendor kernel이 제공하는 일반 proxy API | `PRIMARY`, Android downstream SCM source. [scm.c](https://android.googlesource.com/kernel/msm/%2B/3242618979ee08bc3b7fdac5d3950f7d702be0cd/drivers/soc/qcom/scm.c) | exact TZ allowlist와 runtime table provenance를 찾아야 한다는 interface-centric search를 유도 | public API 존재만으로 주소가 허용되는 것은 아님; on-disk exact allowlist는 known DDRSS를 default-deny하지만 RW table의 runtime state는 UNKNOWN |
| older Qualcomm boot remapper가 stage-2를 우회한 공개 사례 | `PRIMARY`, CVE-2022-22063 researcher report, 2022-12-28. [report](https://github.com/msm8916-mainline/CVE-2022-22063/blob/main/README.md) | protection ordering과 HYP/stage-2를 별도 축으로 유지할 이유 | 이전 세대 analogue이며 SM8150/A90 취약성 증거가 아님 |
| SM8150가 포함된 Qualcomm device에서 secure-processor RPU write access control 결함 이력 | `PRIMARY`, Qualcomm December 2019 Bulletin v1.0, 2019-12-02, CVE-2019-2274. [bulletin](https://www.qualcomm.com/company/product-security/bulletins/december-2019-bulletin) | remote/secure master의 write permission을 별도 검토할 역사적 신호 | 현재 A90 firmware가 vulnerable/unpatched라는 증거가 아님 |
| modern Qualcomm은 SMEM item 603으로 channel/rank/highest-bank-bit/region 정보를 공개할 수 있음 | `PRIMARY`, Linux patch v2, 2025-04-10. [patch](https://lists.openwall.net/linux-kernel/2025/04/10/1754) | ABL strings와 결합하면 high-bit/topology의 값싼 read-only observer 후보 | exact A90에 item/version이 실제 존재하는지는 capture 전 `INFERRED` |
| timing만으로 bank equivalence를 복구해도 complete semantic map은 아님 | `PRIMARY`, Pessl et al., *DRAMA*, USENIX Security 2016. [paper](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_pessl.pdf) | Experiment 014의 강점과 한계를 동시에 지지 | exact implementation ground truth 아님 |
| allocation base/segment에 따라 apparent mapping이 달라질 수 있고 external labeling이 중요 | `PRIMARY`, Jattke et al., *ZenHammer*, USENIX Security 2024. [paper](https://www.usenix.org/system/files/usenixsecurity24-jattke.pdf) | V016/V022R base provenance와 oscilloscope/counter semantic label의 필요성 강화 | AMD/다른 platform 결과의 SM8150 적용은 `INFERRED` |
| conflict graph에서 선형 kernel/rank를 recovery하는 독립 방법 | `PRIMARY`, *Knock-Knock*, 2025. [paper](https://thomasrokicki.github.io/publications/knockknock.pdf) | V027/V028 같은 independent reducer의 방향을 지지 | 저자 방법의 exact mobile timing assumptions는 별도 검증 필요 |
| channel/rank/BG/bank의 component decomposition은 kernel recovery와 별개 문제 | `PRIMARY`, *SUDOKU*, DRAMSec 2025. [paper](https://dramsec.ethz.ch/dramsec25-papers/sudoku-dramsec25.pdf) | “rank-3 = 세 개의 named DRAM coordinates” 과대해석을 막음 | exact target sensor/counter가 없으면 적용 불가 |
| LPDDR4(X)에서 PPR/repair resource와 state가 별도로 존재 | `PRIMARY` vendor proxy, Micron LPDDR4/LPDDR4X datasheet Rev. E, 2020-08. [datasheet](https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/908/MT53E1G16D1FW_2D00_046-AIT--A-MCR-Datenblatt_2800_P010694655_2900_.pdf) | bank kernel은 그대로 두고 row adjacency를 바꾸는 최소 반례 제공 | exact A90 DRAM vendor/part가 미확인이라 `PROXY/INFERRED` |
| Rowhammer susceptibility는 SoC보다 exact DRAM vendor/part/mitigation에 민감 | `PRIMARY`, Frigo et al., *TRRespass*, IEEE S&P 2020. [paper](https://arxiv.org/abs/2004.01807) | 같은 SM8150 양성 사례도 A90 양성/음성을 증명하지 못함 | exact part, refresh, TRR, pattern 없이 전이 금지 |

외부 자료에서 가장 중요한 **새 결론**은 “취약점이 있다”가 아니다. (a) bank hash는 정상적 bijective design일 수 있고, (b) proxy/initiator는 direct APSS access와 별개이며, (c) AOP/PPR/DCC는 기존 route가 표현하지 못한 control/fault **candidate surface**이고, (d) SMEM item 603과 crash dump는 새로운 observer가 될 수 있다는 것이다.

---

## 7. 8개 독립 관점의 주요 반론

### 7.1 SoC / memory-controller architect

- 당연시한 것: timing kernel을 controller의 security-relevant transform으로 부른다.
- 처음 다시 볼 곳: complete-coordinate injectivity와 `B'=B xor H(R)` 같은 정상 bank-hash completion.
- 가장 수상한 UNKNOWN: XPU/NoC/LLCC/DDRSS의 실제 transaction ordering과 instance별 path.
- 최소 반례: low-bit kernel을 보존하면서 전체 PA→DRAM coordinate는 bijective인 한 모델.
- 정말 닫는 증거: channel/rank/BG/bank/row의 독립 label, exact register owner, pre/post-protection 주소 trace.

### 7.2 TrustZone / hypervisor / XPU security researcher

- 당연시한 것: owner=TZ와 raw permission word가 모든 initiator에 대한 deny를 뜻한다.
- 처음 다시 볼 곳: VMIDMT/SID producer, broad+narrow overlap, instance0–3, QHEE stage-2 fault.
- 가장 수상한 UNKNOWN: prior watchdog의 ESR/FAR/ELR과 master/client tag.
- 최소 반례: APSS는 막히지만 HLOS-commandable remote master/client가 broad write grant로 같은 target을 쓰는 한 transaction.
- 정말 닫는 증거: final live policy readback, initiator→NoC→MPU path, master-specific harmless positive/negative control, decoded fault syndrome.

### 7.3 firmware reverse engineer

- 당연시한 것: XBL/DCB selected sites와 literal-first scan이 runtime writer를 대표한다.
- 처음 다시 볼 곳: AOP computed-pointer handlers, HYP/devcfg indirect tables, ABL SMEM DDR protocol, all 152 TZ services.
- 가장 수상한 UNKNOWN: AOP DDR classifier/apply CFG와 SHRM direction-1 indirect caller.
- 최소 반례: unmodelled computed base 또는 indirect call 하나가 DCB/AOP-derived value를 MC/MCCC/DDRSS store로 전달.
- 정말 닫는 증거: complete CFG/indirect-call/copy-primitive recovery, runtime object identity, execution order, final destination.

### 7.4 DRAM mapping / Rowhammer researcher

- 당연시한 것: rank-3 kernel이 complete named coordinate map이고 no-alias가 no-fault-enabler를 뜻한다.
- 처음 다시 볼 곳: V016 pair-level mixture/base carry, semantic decomposition, exact DRAM part/PPR/ECC/TRR.
- 가장 수상한 UNKNOWN: PA24–28의 actual PFN과 row adjacency.
- 최소 반례: bank kernel은 유지되지만 PPR가 victim row adjacency만 바꾸는 상태.
- 정말 닫는 증거: exact SG/PFN, independent bank/channel/rank label, MR/PPR/RAS state, 별도 안전 gate를 통과한 bounded fault experiment.

### 7.5 kernel / driver researcher

- 당연시한 것: direct MMIO가 막히면 kernel이 대신 접근할 interface도 없다.
- 처음 다시 볼 곳: QMP debugfs→AOP, DCC DT microprogram, debugcc MCCC, SMMU/DMA and legacy PIL/SSR.
- 가장 수상한 UNKNOWN: final overlay/live binding과 access-control/SELinux gating.
- 최소 반례: 이미 compiled/bound driver가 HLOS request를 다른 master transaction으로 변환.
- 정말 닫는 증거: final live DT hash, bound-driver/sysfs/debugfs inventory, handler allowlist와 downstream acceptance CFG.

### 7.6 hardware exploit researcher

- 당연시한 것: exploit primitive는 address alias/mutation 하나뿐이다.
- 처음 다시 볼 곳: AOP PASR/refresh integrity, DCC deputy, remote-master permissions, crash-state configuration.
- 가장 수상한 UNKNOWN: protected/online range에 대한 AOP classifier와 remote-master write grants.
- 최소 반례: mapping을 바꾸지 않고 protected/owned DRAM의 refresh 또는 accessibility에 영향을 주는 accepted request.
- 정말 닫는 증거: exact range/ownership check CFG, protected-range negative control, effect observer, recovery boundary. 지금은 live execution 금지.

### 7.7 verification / experimental-design reviewer

- 당연시한 것: retained raw와 deterministic analyzer가 곧 independent falsification이다.
- 처음 다시 볼 곳: V016 even-median/`EXPECTED_*`, V015 per-condition threshold, V029 stimulus range.
- 가장 수상한 UNKNOWN: high-bit pair의 actual physical XOR와 preregistered independent reducer.
- 최소 반례: 16/16 mixture에서 upper-middle 한 sample 변화로 7/7이 5/7이 되는 fixture.
- 정말 닫는 증거: odd-N 또는 명시 median, pair-level distributions, control-only fixed threshold, exact PFN, blind OOS, second observer/reducer.

### 7.8 skeptical blue-team reviewer

- 당연시한 것: “Class C”가 upgrade와 downgrade 모두를 균형 있게 표현한다.
- 처음 다시 볼 곳: 가장 단순한 정상 bijective hash와 가장 값싼 proxy counterexample을 동시에 시험.
- 가장 수상한 UNKNOWN: security relevance 자체와 all-initiator reachability.
- 최소 반례: downgrade 쪽은 injective completion 하나; upgrade 쪽은 harmless proxy write/readback 하나.
- 정말 닫는 증거: 축별 판정 vector, 범위가 고정된 negative controls, actual protected effect 없이는 D/E 금지.

여덟 관점의 공통점은 “현재 결과가 틀렸다”가 아니다. **강한 low-bit mapping 결과와 bounded 음성 결과를 유지하되, 서로 다른 축을 한 문장으로 합치지 말라**는 것이다.

---

## 8. 새로운 가설과 반례

### H1. 관측된 것은 security remapper가 아니라 정상적 bijective bank hash다

- 기존 연구와 다른 점: mutation route를 찾는 대신 가장 단순한 downgrade completion을 먼저 세운다.
- 필요한 전제: full coordinate에서 잃어버린 bit가 다른 row/column coordinate에 보존됨.
- supporting evidence: 강한 same-selection kernel, complete alias 미관측, Qualcomm patent의 row-dependent bank hash.
- contradicting evidence: exact silicon full map/owner가 없으므로 직접 반박도 지지도 아직 불완전.
- 가장 싼 discriminator: 3-address conflict graph + independent semantic label/counter; static owner/register attribution.
- 성공 시 의미: `C-MAP`은 유지하지만 security-boundary class는 downgrade.
- 실패 시 닫히는 공간: 정상 linear bijective completion 일부.
- information gain / 위험: 높음 / host-only 분석과 read-only observer 설계.
- 새 관측 능력·선행정보: channel/rank/BG/bank label, exact PA.

### H2. XPU protection은 initiator/path-specific이며 alternate master가 다른 grant를 가진다

- 기존 연구와 다른 점: address가 아니라 initiator와 overlapping policy를 변수로 둔다.
- 필요한 전제: broad permission의 non-owner client가 실제 remote/DMA master에 매핑되고 HLOS가 그 master를 command할 수 있음.
- supporting evidence: instance별 narrow-region 비대칭, broad write vectors, generic Qualcomm VMIDMT/XPU topology.
- contradicting evidence: exact actor naming과 commandable path가 없고 instance0 narrow deny가 direct APSS non-return과 일치.
- 가장 싼 discriminator: host-only XPU analyzer repair와 exact DT/firmware master-tag producer mapping.
- 성공 시 의미: 새 proxy/deputy route; 즉시 D/E는 아님.
- 실패 시 닫히는 공간: decoded master/client 집합에 대한 alternate-initiator path.
- information gain / 위험: 매우 높음 / host-only.
- 새 관측 능력·선행정보: full client vectors, overlap precedence, final policy observer.

### H3. AOP mailbox가 mapping이 아닌 PASR/refresh integrity surface를 제공한다

- 기존 연구와 다른 점: address alias 대신 refresh/power ownership을 본다.
- 필요한 전제: generic QMP client가 final image에서 bound/reachable하고 AOP가 request를 protected/online range에 적용.
- supporting evidence: exact compiled kernel client, embedded compatible string, exact AOP DDR/PASR vocabulary·partial parser code와 별도의 computed-register callback.
- contradicting evidence: live debugfs/SELinux/binding 미확인; AOP range classifier가 요청을 거부할 수 있음; mapping mutation 증거 없음.
- 가장 싼 discriminator: **실행 전** exact AOP handler→classifier→apply CFG와 final DT overlay 정적 복구.
- 성공 시 의미: 별도 `DDR-INTEGRITY-CONTROL` route; protected effect가 있어야 class upgrade 검토.
- 실패 시 닫히는 공간: 해당 message class/range의 proxy path.
- information gain / 위험: host-only 단계 매우 높음; live request는 중~고위험이고 별도 gate 필요.
- 새 관측 능력·선행정보: final binding, ownership/range semantics, disposable normal allocation control, rollback.

### H4. prior direct-load non-return의 실제 원인은 XPU가 아니라 QHEE stage-2 abort다

- 기존 연구와 다른 점: denial의 존재가 아니라 denial layer를 식별한다.
- 필요한 전제: retained HYP fault record가 exact probe와 시간/주소로 결박됨.
- supporting evidence: upload log가 HYP data-abort/FAR/ESR/ELR record 존재를 가리키며 XPU/NoC log는 해독되지 않음.
- contradicting evidence: fault value와 timestamp가 아직 없고 instance0 narrow XPU raw policy도 deny와 양립.
- 가장 싼 discriminator: retained dump parser로 ESR/FAR/ELR/master/time 복구; 새 device action 불필요.
- 성공 시 의미: Route-2 causal narrative 재작성, CVE analogue 평가의 layer가 정확해짐.
- 실패 시 닫히는 공간: 해당 retained incident에 대한 stage-2 explanation.
- information gain / 위험: 매우 높음 / host-only.
- 새 관측 능력·선행정보: HYP log format/key/decompression와 exact incident correlation.

### H5. DCC는 APSS direct load와 다른 initiator로 controller state를 관측/변경할 수 있다

- 기존 연구와 다른 점: DCC microprogram bus master를 별도 initiator로 본다.
- 필요한 전제: final live DCC가 target range를 허용하고 list를 안전하게 보존/복원할 수 있음.
- supporting evidence: exact config/source, 204R+46W DT descriptors, retained DCC entries.
- contradicting evidence: 현재 target list에 known remapper가 없고 DCC 자체 설정이 MMIO/SRAM writes를 요구하며 XPU path도 모름.
- 가장 싼 discriminator: live 실행이 아니라 exact driver binary CFG, DT/overlay merge, existing-list state/rollback design.
- 성공 시 의미: nonfatal observer 또는 deputy route.
- 실패 시 닫히는 공간: exact DCC master/path가 접근 가능한 address class.
- information gain / 위험: static은 중간/낮음; live는 고위험. 이번 pass에서 실행 금지.
- 새 관측 능력·선행정보: DCC master security tag, final binding, list atomicity, recovery proof.

### H6. DRAM die의 PPR/spare-row가 bank kernel을 유지하며 row adjacency만 바꾼다

- 기존 연구와 다른 점: SoC register가 아니라 die 내부 repair state를 본다.
- 필요한 전제: exact LPDDR4X part가 PPR을 지원하고 repair가 적용되어 있거나 runtime 가능.
- supporting evidence: LPDDR4X vendor proxy와 일반 architecture; current timing observer의 row/PPR blindness.
- contradicting evidence: exact part/MR25/repair evidence가 0이며 alias/fault도 미관측.
- 가장 싼 discriminator: exact DRAM identity와 MR/PPR/RAS observer 설계, 공개 part documentation.
- 성공 시 의미: mapping security class와 별개로 adjacency/fault model 수정.
- 실패 시 닫히는 공간: exact part/current repair state의 PPR 반례.
- information gain / 위험: 중~높음 / 초기 read-only; hard-PPR 실행은 금지.
- 새 관측 능력·선행정보: part/vendor, MR8/MR25, ECC/EDAC/RAS state.

### H7. OPP/PASR/SSR 중 하나가 suspend와 다른 mapping/control state를 만든다

- 기존 연구와 다른 점: perturbation 크기가 아니라 handler/code-path identity로 transition을 선택한다.
- 필요한 전제: 해당 transition이 실제로 발생하고 동일 physical pair를 전후 측정 가능.
- supporting evidence: exact AOP frequency/PASR vocabulary와 partial parser·handler code; V015 DDR frequency axis는 한때 static vote로 vacuous; V019는 suspend path뿐. Sender→apply-handler dispatch는 아직 supporting fact가 아니라 discriminator다.
- contradicting evidence: low-bit relation은 여러 기존 condition에서 안정적이고 mutation evidence는 없음.
- 가장 싼 discriminator: host-only transition matrix와 receipt design; actual OPP/state observer부터 구축.
- 성공 시 의미: runtime mutable mapping/control route.
- 실패 시 닫히는 공간: **그 exact transition과 measured coordinates**만.
- information gain / 위험: 설계 단계 높음/낮음; live 단계 중간, 별도 gate.
- 새 관측 능력·선행정보: OPP/PASR/SSR receipt, exact PA pin, before/after controller state.

### H8. SMEM item 603/ABL final-DT path가 high-bit topology의 독립 ground truth를 제공한다

- 기존 연구와 다른 점: 공격 route가 아니라 여러 가설을 동시에 가르는 measurement hypothesis다.
- 필요한 전제: exact A90 boot에서 compatible item/version과 final properties가 존재.
- supporting evidence: exact ABL strings의 rank/HBB/DDR Info protocol, modern Qualcomm public struct.
- contradicting evidence: 현재 retained final-DT snapshot에 해당 property가 없고 item capture가 없음.
- 가장 싼 discriminator: host-only ABL protocol/dataflow parser; 이후 read-only SMEM/final-DT inventory.
- 성공 시 의미: rank/highest-bank-bit/region cross-check, PA28 model과 allocation 설계 개선.
- 실패 시 닫히는 공간: 이 boot의 item/version observer route.
- information gain / 위험: 매우 높음 / host-only 또는 read-only.
- 새 관측 능력·선행정보: exact item ID/version/layout, final overlay hash.

### H9. protection check가 transform 뒤에 있어 security alias가 구조적으로 차단된다

- 기존 연구와 다른 점: exploit route가 아니라 protection-order downgrade를 적극 시험한다.
- 필요한 전제: XPU/MC target check가 final translated address/security tag에 적용되거나 full map이 injective.
- supporting evidence: no complete alias/bypass와 normal bijective bank-hash model. Target-side XPU라는 일반 구조는 SMMU/VMIDMT 뒤 system-bus destination 검사를 뜻할 수 있을 뿐 MC의 system-PA→DRAM-coordinate transform 뒤 검사를 증명하지 않으므로 supporting evidence에서 제외한다.
- contradicting evidence: exact block ordering과 translated address trace가 없고, XPU check가 MC bank/row mapping보다 앞일 가능성도 현재와 양립한다.
- 가장 싼 discriminator: patent/driver/firmware block graph + master/path mapping; live write가 필요 없는 구조 감사.
- 성공 시 의미: 현재 위협모델의 핵심 precondition이 닫혀 Class C조차 security taxonomy에서 과함.
- 실패 시 닫히는 공간: check-after/injective completion 일부.
- information gain / 위험: 높음 / host-only.
- 새 관측 능력·선행정보: block ordering, address stage naming, fault address semantics.

### H10. retained crash/upload가 새 fatal probe 없이 refusal mechanism을 식별할 수 있다

- 기존 연구와 다른 점: 더 많은 crash를 내기보다 이미 남은 observer data의 정보량을 높인다.
- 필요한 전제: HYP/XPU/NoC payload가 해독 가능하고 incident와 결박 가능.
- supporting evidence: retained upload parser가 관련 log section과 fault-field 문자열을 이미 찾음.
- contradicting evidence: 일부 TZ log는 encrypted/unparsed이고 exact correlation receipt가 없음.
- 가장 싼 discriminator: host-only format reverse engineering과 known-control crash 비교.
- 성공 시 의미: direct-aperture conclusion의 cause, master, address, ordering을 동시에 개선.
- 실패 시 닫히는 공간: 현재 retained format/key로 복구 가능한 observer route.
- information gain / 위험: 매우 높음 / host-only.
- 새 관측 능력·선행정보: log format, encryption/compression, timestamp correlation.

---

## 9. Class C upgrade/downgrade stress test

### 9.1 Class C가 너무 낮을 수 있는 방향

다음 연결이 확인되면 D/E 방향을 검토할 수 있다. 현재는 어느 것도 완성되지 않았다.

1. **Alternate-initiator chain**

   `HLOS-commandable proxy -> remote/DMA/AOP/DCC master -> remapper/controller write -> controlled final destination`. Broad XPU client write vectors와 AOP/DCC surface는 첫 두 링크 후보일 뿐, exact actor/reach/effect가 없다.

2. **AOP integrity chain**

   `Normal-World request -> AOP accepts protected/online address -> refresh/PASR/training effect -> protected data integrity/availability impact`. Compiled sender와 AOP vocabulary·partial parser/computed callback은 독립적으로 보이지만 둘을 잇는 exact dispatch, live binding, protected-range acceptance와 effect가 없다. 이것은 연결될 경우 mapping alias 없이도 security-relevant할 수 있다.

3. **Transform/protection-order chain**

   `controlled mutation -> protection checks old/system PA -> downstream transform selects another protected coordinate`. Mutation, ordering, complete coordinate collision 모두 미증명이다.

4. **QHEE/stage-2 chain**

   Direct refusal가 stage-2라면 older boot-remapper bypass와 같은 class의 구조 질문이 다시 열린다. 그러나 exact A90 bypass나 mutable remapper는 없다.

5. **DCC/diagnostic deputy chain**

   DCC 또는 Samsung diagnostic path가 APSS와 다른 security tag로 target에 접근할 수 있다면 direct-load negative를 우회할 수 있다. 현재 DCC target list에 remapper가 없고 새 실행도 하지 않았다.

Class D로 올리려면 적어도 **보호 경계에 도달한 transformed transaction과 뒤쪽 차단**이 필요하다. Class E에는 **보호된 내용의 실제 unauthorized read/write 또는 isolation bypass**가 필요하다. 현재 retained evidence에는 둘 다 없다.

### 9.2 Class C조차 과할 수 있는 방향

1. **정상 bank hash.** 관측된 low-bit relation은 performance-oriented bank/BG hash로 완전히 설명 가능하다.
2. **complete injectivity.** bank output에서 사라진 주소 정보가 row/column/rank에 보존되면 distinct PA는 distinct complete coordinate다.
3. **check-after-transform.** exact target에서 MC/die의 별도 access check가 final DRAM coordinate에 적용된다는 증거가 나오면 위협모델의 check-before 조건은 성립하지 않는다. 현재 target-side XPU 사실만으로는 이를 말할 수 없다. XPU는 SMMU 이후이면서도 MC bank/row transform 이전일 수 있다.
4. **관측기 confound.** 일부 timing class가 LLCC/NoC의 결과라면 DRAM transform 주장은 더 좁아진다.
5. **high-bit artifact.** V016의 base carry와 upper median 때문에 PA25–27 부분이 사라져도 low-bit `C-MAP`만 남는다.
6. **no mutation authority.** signed boot route는 실제로 강한 closure이고, exact SCM IO의 on-disk table도 known DDRSS를 default-deny한다. 다만 RW allowlist의 runtime writer/value를 닫기 전에는 SCM IO를 같은 등급의 closure로 둘 수 없다. 그 확인과 다른 proxy closure가 끝나면 “observable but immutable normal mapping”이 더 정확해진다.

### 9.3 ordinal class 대신 권고하는 판정 vector

| 축 | 현재 판정 | 근거 범위 |
|---|---|---|
| `MAP-KERNEL-PA13_23` | **STRONGLY SUPPORTED / bounded timing-equivalence** | Experiment 014, V027, V029 low-bit 8/8 |
| `MODEL-RANK-FLOOR-THROUGH-PA24` | **SUPPORTED / bounded allocation-model coordinates** | V028 preregistered triple includes PA24; semantic DRAM attribution은 아님 |
| `MAP-HIGH-PA25_28` | **MODEL-SUPPORTED, PHYSICAL-PROVENANCE BLIND** | V016 취약, V022R conditional, V029 미자극 |
| `SEMANTIC-COORDINATES` | **UNKNOWN** | channel/rank/BG/bank/row label 없음 |
| `COMPLETE-COORDINATE-ALIAS` | **NOT OBSERVED IN BOUNDED V018; GLOBAL UNKNOWN** | one state, bits6..27, 176 candidates |
| `MUTABILITY` | **UNKNOWN** | register before/after 없음; V015는 4 invariant + `v2321-L762 REPEAT_REQUIRED` |
| `APSS-DIRECT-REACH` | **INSTANCE0 NONRETURNING; CAUSE UNKNOWN** | one address family, zero-load control |
| `OTHER-INITIATOR/PROXY-REACH` | **OPEN** | AOP/DCC/DMA/remote; SCM IO on-disk allowlist는 default-deny이나 RW runtime table/writer는 UNKNOWN |
| `FINAL-XPU/POLICY-PATH` | **UNKNOWN** | static raw policy는 있으나 client/path/live readback 없음 |
| `PROTECTION-ORDER` | **UNKNOWN** | injective/check-after와 exploit model 모두 양립 |
| `PROTECTED-EFFECT/BYPASS` | **NOT OBSERVED** | D/E 증거 없음 |
| `FAULT-ENABLER` | **STATE/EXPERIMENT NOT CREATED** | PPR/ECC/TRR/Rowhammer observer·실험 없음 |
| `DDR-INTEGRITY-CONTROL` | **STATIC CANDIDATE SURFACE, DISPATCH/EFFECT UNPROVED** | exact QMP sender와 AOP vocabulary/partial handler/computed callback의 아직 미연결된 사실들 |

따라서 기존 이름을 유지해야 한다면 “`Class C`가 맞다”보다 **`C-MAP only; C-ALIAS/C-MUTATION/C-REACH/C-ORDER unresolved`**가 정확하다.

---

## 10. measurement capability gap

아래의 `1/2/3`은 요청에서 요구한 구분이다.

- `1`: 현상이 없어서 관측되지 않음
- `2`: 현재 observer로 식별할 수 없음
- `3`: 상태/경로 자체를 아직 만들지 않음

| 질문 | 현재 분류 | 이유 |
|---|---|---|
| V018 exact offsets의 simple storage alias | `1 — bounded` | positive control이 fired한 observer에서 176 candidate가 모두 DISTINCT |
| global/PA28+/state-dependent complete alias | `2 + 3` | physical range와 state coverage가 없고 observer가 full coordinate를 보지 못함 |
| PA13–23 same-selection kernel | 현상 관측됨 | 강한 direct timing evidence |
| PA24–28 physical relation | `2` | exact PFN/SG와 base-aware physical XOR가 없음 |
| channel/rank/BG/bank/row 의미 | `2` | timing kernel output에 semantic label이 없음 |
| output-basis/affine/full-map mutation | `2` | label/kernel observer가 이 변화를 식별하지 못함 |
| OPP/PASR/SSR별 mapping 변화 | `3`, 일부 `2` | exact transition을 receipt로 만들지 않았고 same PA before/after observer도 없음 |
| deep-suspend content movement | `1 — two exact acquisitions` | 같은 uninterrupted boot의 두 별도 acquisition에서 moved=0; 다른 state로 확장 금지 |
| direct-load refusal mechanism | `2` | syndrome/master/fault-address positive control 없음 |
| instance1–3 APSS direct reach | `3` | 자극하지 않음 |
| remote/DMA/AOP/DCC reach | `2 + 3` | master/path decoder와 harmless live control이 없음; DCC는 write side effect 때문에 보류 |
| final XPU policy/overlap precedence | `2` | boot records만 있고 runtime readback 없음 |
| AOP generic QMP live binding/acceptance | `2 + 3` | compiled code/DT string은 있으나 final overlay, SELinux, acceptance를 확인하지 않음 |
| SCM IO를 통한 known DDRSS reach | `2 + 3`, 단 static default-deny | on-disk 81-entry allowlist에 해당 band가 없지만 RW runtime table 값/readback과 writer가 미관측이고 해당 request도 실행하지 않음 |
| PPR/ECC/TRR/die repair | `2 + 3` | exact part/state observer와 experiment가 없음 |
| Rowhammer susceptibility | `3` | hammer/activation/flip/syndrome experiment가 없음. “부재”가 아님 |

### 10.1 먼저 만들어야 할 observer

1. **Exact SG/PFN oracle.** dma-buf/ION allocation의 실제 segment, PFN, base, length를 kernel-side에서 구조적으로 읽고 acquisition receipt에 결박한다. V016/V022R/high-bit/OOS 네 문제를 동시에 판별한다.

2. **Full XPU policy/path decoder.** raw owner/read/write word, 모든 client vector, standard/nonstandard slot, region overlap, instance, boot order를 손실 없이 JSON으로 직렬화한다. actor 이름을 증거 없는 HLOS/MSA label로 고정하지 않는다.

3. **HYP/XPU/NoC fault decoder.** retained crash/upload에서 ESR/FAR/ELR, faulting address, master/security tag, timestamp를 복원하고 exact probe receipt와 결박한다.

4. **AOP dataflow analyzer.** computed pointer, callback table, mailbox class/resource/key parser, range/ownership classifier, final store를 모두 추적한다. literal hit count를 closure로 쓰지 않는다.

5. **ABL/SMEM DDR-info parser.** item/version, channel/rank/HBB/region data를 exact final DT와 대조한다. 존재하지 않으면 명시적 negative가 된다.

6. **Independent DRAM semantic observer.** 3-address conflict graph, same-row control, anchor rotation과 함께 controller counter 또는 외부 logic/oscilloscope label을 사용한다.

7. **Transition receipt framework.** cold/warm/recovery/suspend/OPP/PASR/SSR/crash 각각을 별도 state로 결박하고 동일 physical pair와 policy snapshot을 before/after 비교한다.

8. **DCC state-preservation observer/design.** 새 list 실행 전 final overlay, live binding, existing SRAM/list, auto-enable, write descriptors와 rollback을 정적으로 완전히 복구한다. 이 능력이 생겨도 자동 실행 권한은 아니다.

### 10.2 analyzer가 반드시 실패시켜야 할 adversarial fixtures

- even-N 16/16 mixture와 upper/lower median 차이
- allocation base carry로 nominal PA XOR가 섞이는 경우
- invertible output-basis 변화와 affine constant
- row-only/PPR permutation
- condition별 absolute latency만 변하고 kernel은 같은 경우
- broad XPU client vector가 narrative formatter에서 사라지는 경우
- overlapping policy 중 실제 initiator path가 하나뿐인 경우
- indirect/computed pointer가 literal search를 우회하는 경우

이 fixture에서 “INVARIANT”나 “NO WRITER”를 내는 analyzer는 scientific verifier가 아니라 regression replayer다.

---

## 11. information-gain 기준 다음 연구 우선순위

점수는 `IG` 1–5, 실패 결과의 유용성 `N` 1–5다. `Device effect`가 `none`인 것부터 완료해야 한다.

| 순위 | 연구/측정 능력 | 동시에 가르는 가설 | IG / N | Device effect | 진행 조건 |
|---:|---|---|---:|---|---|
| 1 | XPU analyzer를 full client-vector + overlap + all-instance로 수리하고 broad-write fixture 추가 | H2, H9, direct-denial interpretation | 5 / 5 | none | exact TZ pin과 raw-record equality |
| 2 | exact AOP handler/callback/computed-pointer/classifier/apply CFG 완전 복구 | H3, H7, runtime-writer completeness | 5 / 5 | none | AOP SHA/VA-file mapping, indirect-call accounting |
| 3 | retained HYP/XPU/NoC crash payload와 prior incident 인과 복구 | H4, H9, refusal cause, protection order | 5 / 5 | none | dump identity, format/key, timestamps |
| 4 | exact SG/PFN oracle의 source-backed 설계·negative tests | H1, high-bit model, V016/V022R, real OOS | 5 / 5 | none in this phase | allocation API/SG lifetime, no-write contract |
| 5 | all 152 TZ SMC service와 kernel ioctl/mailbox consumer census | H2, H3, proxy closure | 4 / 5 | none | exact table boundary, handler dedup, indirect dispatch |
| 6 | ABL/SMEM item603/final-DT DDR-info parser | H8, rank/HBB/topology, allocation design | 4 / 5 | none; later read-only | exact item layout/version and final overlay hash |
| 7 | V016 reducer repair + truly high-bit blinded OOS design | H1, physical PA24–28, observer defect | 4 / 5 | none in design | odd-N/mixture report, PFN prerequisite, independent prereg commit |
| 8 | per-transition state matrix와 receipt contract | H3, H7, deep-suspend non-subsumption | 4 / 5 | none in design | 각 handler/path를 별도 experiment로 정의 |
| 9 | DCC exact binary/DT/overlay/auto-enable와 current-list preservation 정적 감사 | H5, nonfatal observer feasibility | 3 / 4 | none | live execution은 별도 write gate 전 금지 |
| 10 | 이후에만 master-specific harmless read/positive-negative control 검토 | H2, H4, H5 | 5 / 5 | possible MMIO/proxy effect | final policy, disposable target, rollback/final-health gate |
| 11 | exact DRAM part/MR/PPR/ECC/RAS read-only observer | H6, fault-enabler taxonomy | 4 / 4 | read-only candidate | vendor/part identity와 safe interface |
| 12 | adjacency/retention 및 bounded Rowhammer | H6와 실제 fault primitive | 3 / 3 | high activity/risk | 별도 안전·열·데이터·복구 gate; 가장 마지막 |

### 11.1 즉시 실행하면 안 되는 “그럴듯한” 후보

- **DCC live probe:** source와 DT가 write-capable하므로 read-only가 아니다.
- **debugcc `clk_measure`:** parent-selection/GCC/bus-vote side effect 가능성이 있고 MCCC recursive regmap access는 range error일 수 있어, 성공하는 pure read-only observer로 볼 수 없다.
- **generic AOP QMP request:** sender→apply-handler dispatch, range/ownership과 final binding이 아직 닫히지 않았다.
- **remapper write:** mutation register/ordering/effect observer가 없다.
- **PPR/hammer:** exact part, adjacency, ECC/TRR, thermal/recovery evidence가 없다.

이들의 보류는 연구 회피가 아니다. 같은 UNKNOWN을 더 싸고 독립적으로 가르는 host-only work가 아직 남아 있기 때문이다.

---

## 12. 현재 결론

이번 감사로 `CLASS C (TRANSFORM ONLY)`를 그대로 방어하거나 D/E로 올릴 근거는 나오지 않았다. 더 정확한 결론은 다음과 같다.

1. **가장 강하게 살아남는 결과는 `C-MAP`이다.** PA13–23의 same-selection kernel, PA24를 포함한 V028의 preregistered model-coordinate rank floor 3, V029의 PA13–23 8/8 OOS는 서로 범위를 섞지 않으면 강하다.

2. **high-bit 물리 결론은 재개방해야 한다.** V016의 두 conflict label은 16/16 mixture에서 upper median에 의존하고, allocation offset XOR는 actual PA XOR가 아니다. V022R은 개선됐지만 observed PFN이 없어 conditional이다. V029는 high bit를 시험하지 않았다.

3. **complete alias나 protected bypass는 관측되지 않았다.** V018은 exact tested state/offset에서 강한 bounded negative다. 그러나 global injectivity, PA28+, state-dependent alias까지 증명하지는 않는다. Class D/E 증거는 0이다.

4. **direct aperture 결론은 좁혀야 한다.** 정확한 표현은 “APSS의 exact instance0 load harness가 값을 반환하지 않았다”이다. XPU 인과, 네 instance, 다른 initiator/proxy까지 확장할 수 없다.

5. **XPU 정적 근거는 raw-policy fact와 actor/path 해석을 분리해야 한다.** Instance0 narrow policy는 실재하지만 broad client vectors가 기존 report에서 소실되고, instance1–3은 동일 narrow coverage가 없다. all-master denial과 final live policy는 UNKNOWN이다.

6. **deep suspend는 다른 transition을 subsume하지 않는다.** V019는 같은 uninterrupted boot의 두 별도 suspend acquisition에서 content tag가 유지된다는 강한 결과일 뿐, AOP OPP/PASR, modem SSR, recovery→system, crash/upload를 닫지 않는다.

7. **DCB/XBL은 두 갈래로 판정해야 한다.** 서명된 `xbl_config` 교체/boot route는 강하게 닫혀 있다. 하지만 existing XBL/DCB의 global runtime writer absence는 bounded static model 밖에서 UNKNOWN이다.

8. **새 candidate surface/hypothesis가 세 묶음 생겼다.** (a) 아직 sender→apply dispatch가 미연결인 QMP/AOP/PASR indirect DDR control 후보, (b) instance/path/client-specific XPU와 remote/DMA deputy, (c) DCC/debugcc 같은 alternate kernel/initiator path다. 어느 것도 아직 완성된 route, mutation, protected effect 또는 bypass를 증명하지 않는다. DCC/debugcc는 read-only가 아니므로 실행 후보가 아니다.

9. **새로 강해진 narrow negative도 있다.** Exact TZ `SCM_IO_READ/WRITE`의 on-disk 81-entry allowlist에는 known DDRSS/remapper band가 없다. 이 static default-deny는 해당 proxy의 우선순위를 낮추지만, table이 RW segment에 있으므로 runtime value/writer를 확인하기 전에는 route를 닫지 않는다. 반면 signed boot replacement route와 V018의 exact simple-alias corpus는 각자의 bounded 범위에서 강하게 닫힌다.

10. **taxonomy를 바꾸는 것이 현재 최선이다.** 단일 ordinal `Class C` 대신 `MAP / ALIAS / MUTATION / REACH / POLICY-PATH / ORDER / PROTECTED-EFFECT / FAULT-ENABLER` vector를 사용해야 한다. 현재 판정은 다음 한 줄로 요약된다.

> **Bounded low-bit `C-MAP` strongly supported; high-bit physical provenance, mutation, alternate-initiator reach, final policy/path, protection ordering, complete global alias, and fault-enabler state remain unresolved; no Class D/E effect observed.**

첫 pass의 다음 행동은 새로운 device write가 아니라 **XPU analyzer repair, AOP computed-dataflow closure, retained fault decode, exact SG/PFN oracle와 SMEM topology observer 설계**다. 이번 감사에서는 device/controller/protected-memory action을 전혀 수행하지 않았고, 다른 branch/worktree의 진행 중 파일도 수정하지 않았다.
