# Autonomous SM8150 Research Loop Contract

## Objective

현재 분류가 정확히 `CLASS C (TRANSFORM ONLY)`인 동안, 현재 증거가 허용하는
가장 높은 정보량의 다음 비중첩 실험을 자율적으로 선택하고 실행한다. 각
iteration은 검증, 독립 hostile review, 원자적 commit, 분류 재평가까지 완료한
뒤 다음 iteration으로 반복한다. 대상은 오직 `SM-A908N/SM8150`이다. 다른
device, 특히 `S20+`와 `S22+`, 는 `OUT OF SCOPE`이다.

이 문서는 approval request가 아니다. Commentary status update는 informational
only이며 approval 요청으로 해석하지 않는다.

## Evidence and claim discipline

모든 사실과 결론은 다음 정확한 label 중 하나를 사용한다.

- `PROVED`: exact input/source/artifact와 재현 가능한 검사가 직접 입증한 것.
- `SUPPORTED`: 독립적인 규약, 모델, 반복 관찰이 지지하지만 이 iteration의
  직접 증명은 아닌 것.
- `HYPOTHESIS`: 다음 discriminator로 시험할 명시적 예측.
- `UNKNOWN`: 아직 측정·복원·검증되지 않았거나 scope 밖인 것.
- `REFUTED`: 명시된 모델·범위·조건 안에서 부정된 것. 전역 부재나 writer
  부재를 뜻하지 않는다.

Evidence는 exact target binding, input size/hash, VA/file/PA mapping, code/data
range, command, build, timestamp, repetition, negative control, review result와
함께 보존한다. Public output에는 private absolute path, firmware bytes, secret,
device credential를 넣지 않는다. Private artifact와 public redacted manifest를
분리한다. 정적 증거, runtime observation, authority/ownership, semantic
interpretation, execution은 서로 합치지 않는다.

## Iteration algorithm

각 loop는 아래 순서를 기계적으로 따른다.

1. `SNAPSHOT`: repository HEAD/dirty tree, worktrees, agents, active efforts,
   target identity, retained artifacts와 각 hash를 기록한다.
2. `UNKNOWN INVENTORY`: critical `UNKNOWN`을 evidence/source/range별로
   열거하고, 이미 검증된 claim과 필요한 discriminator를 분리한다.
3. `CANDIDATE ENUMERATION`: non-overlapping host/static, source-backed,
   observation, reversible normal-RAM 후보를 만든다. 각 후보는 목표 unknown,
   입력/출력, negative controls, stop gate, rollback/recovery를 가진다.
4. `SCORING`: information gain, discriminating power, success probability,
   cost, risk, dependency, reuse value를 명시적으로 점수화한다. 가장 높은
   expected information value를 가진 후보 하나를 선택한다. 동률이면 risk,
   cost, dependency가 낮고 재사용성이 높은 후보를 선택한다.
5. `CONTRACT`: exact target/range, pre-capture, bounded action, expected
   positive/negative result, failure state, rollback/reconcile procedure,
   disclosure rule을 기록하고 deterministic artifact names를 예약한다.
6. `EXECUTE`: 아래 자동 authority 범위 안에서만 실행한다. 범위 밖이면
   실행하지 않고 해당 pause gate를 기록한다.
7. `PRIMARY VERIFY`: exact hashes/mappings, decoder/model, negative controls,
   repetitions, public/private separation, deterministic manifest와 claim
   labels를 검증한다.
8. `INDEPENDENT HOSTILE REVIEW`: checkpoint에서 다른 agent/worktree 또는
   독립 재검사로 inputs, raw bytes/words, range boundaries, decoder masks, counts, claim
   levels, safety and non-overlap를 다시 확인한다. host-only 미세 변경은 위
   fast path에 따라 checkpoint 전까지 root review와 targeted test로 대체할 수
   있다. 불일치면 fix-and-review를 반복하고 live effect 전에는 닫는다.
9. `COMMIT`: PASS 후 public/private artifact contract와 state/log를 하나의
   clean atomic commit으로 기록한다. Commit hash, residual `UNKNOWN`, next
   scored candidates를 보고한다.
10. `RECLASSIFY`: 결과에 따라 `PROVED/SUPPORTED/HYPOTHESIS/UNKNOWN/REFUTED`
    를 갱신하고 `CLASS C (TRANSFORM ONLY)`를 유지할지 평가한 뒤 loop를
    반복한다.

## Proportional verification and fast path

검증 강도는 action의 위험과 claim의 크기에 비례시킨다. 고정 mock 값, 출력
형식, decoder 보조 함수처럼 device effect가 없는 host-only 미세 변경은 관련
targeted test와 root review만 통과하면 여러 개를 하나의 checkpoint로 묶을 수
있다. 각 미세 변경마다 full suite, 별도 hostile-review 문서, 독립 manifest를
반복하지 않는다.

다음 checkpoint에서만 combined/full suite와 독립 hostile review를 필수로
실행한다.

- 새 live device effect 직전;
- rollback/no-replay/target binding/boot identity 경로 변경 후;
- 새로운 `PROVED` 또는 `REFUTED` claim을 발행하기 직전;
- security classification 또는 보호 경계 해석이 바뀔 때;
- 여러 host-only 변경을 통합해 다음 iteration을 시작할 때.

런타임에서 kernel이 정하는 값은 오래된 mock의 숫자와 동일할 필요가 없다.
고정 source path에서 엄격히 파싱하고, action 인자와 결과에 동일 값을
교차바인딩할 수 있으면 그 관계를 검증한다. stale 숫자 자체를 권한 조건으로
승격하지 않는다. 안전과 무관한 provenance 중복, 동일 필드의 다중 validator,
미세 변경별 전체 corpus 재실행은 새로운 반례를 구분하지 못하면 생략한다.

항상 유지하는 최소 gate는 exact A90 binding, current boot hash, durable
no-replay journal, bounded one-shot effect, panic/sysctl 원상복원, artifact hash,
rollback/recovery path다. 이 최소 gate는 속도를 이유로 생략하지 않는다.

## Automatic authority (no repeated approval)

이 GOAL의 loop는 host-only/read-only로 제한되지 않는다. GOAL이 유효한 동안
host-only/static iteration은 retained artifact의 exact target identity/hash
binding으로 충분하며 현재 live device binding을 요구하지 않는다. Device
action은 매 action 직전에 exact `A90/SM-A908N`을 재열거하고 bind해야 한다.
그 조건 아래 bounded/evidence-backed action은 이 project와 exact A90에 대해
자동 실행·측정·rollback/reconcile할 수 있다. 이는 다른 repository의
contract, 특히 `android-native-init-lab`의 별도 authority를 주장하거나
대체하지 않는다.

- host-only static analysis, reverse engineering tooling, decoder work,
  reproducible tests와 deterministic public manifests;
- retained private artifacts의 read-only parsing, hashing, redaction;
- current target contract가 허용하는 exact-bound A90 shell/serial/ADB/ACM
  commands와 read-only observation;
- controlled normal-RAM reads/writes/timing/cache/DMA tests;
- 원본을 capture한 temporary sysfs/debugfs/module/governor/parameter state;
- journal된 reboot/reconnect와 intentionally induced recoverable reset;
- original state가 capture되고 exact rollback과 independent recovery path가
  proven/untouched인 reversible research-kernel/runtime configuration 또는
  boot-state change;
- exact register/effect/width/pre-state/reset-or-rollback와 recovery가
  established된 source-backed controller writes.

각 action은 bounded target, pre-capture, stop condition, durable no-replay
journal, exact rollback/recovery와 independent recovery proof를 가져야 한다.
이 조건을 만족하는 위 action은 per-step operator approval 없이 실행할 수
있다. `PASS_GO`, manifest, test pass, hash 또는 user-observed boot health만으로
live authority를 추론하지 않으며, device identity/scope/expiry gate와
recovery proof를 생략하지 않는다.

## Mandatory pause and notify gates

다음 조건이면 즉시 pause하고 상태와 필요한 user/external action을 notify한다.

- target identity가 ambiguous하거나 exact A90 binding이 사라짐;
- 다른 device가 연결/선택됨 (`S20+`, `S22+` 포함);
- recoverability가 established되지 않은 action, potential permanent damage
  또는 data loss;
- recovery/Download/boot-chain recovery path를 impair할 수 있는 action;
- bootloader, GPT, RPMB, QFPROM, security partition 접근/변경;
- persistent security/identity storage 접근/변경;
- source-backed proof 없는 unknown controller write;
- XPU/SMMU/SCM ownership/security mutation;
- EL2/EL3/protected-memory mutation 또는 secret dumping;
- security-boundary bypass indicator;
- classification이 `CLASS C (TRANSFORM ONLY)`에서 이탈함;
- disclosure trigger 또는 취약점/우회 가능성의 외부 coordination 필요;
- unrelated dirty-tree conflict 또는 ownership/file/range/semantic collision;
- credential, user login, user physical action 또는 외부 authority가 필요함.

Transient reset/hang 자체는 watchdog/manual-independent recovery가 이미
proven하고 untouched인 경우 gate가 아니다. Recovery가 failed/uncertain이면
즉시 gate로 전환하고 pause한다. 이미 효과가 있었을 수 있는 write는 replay하지
않고 journal/reconcile부터 수행한다. `UNKNOWN`을 권한으로 바꾸거나 범위를
넓히지 않는다.

## Potential bypass behavior

보호 경계 우회 가능성을 시사하는 결과가 나오면 즉시 상태를
`POTENTIAL_SECURITY_BOUNDARY_BYPASS`로 바꾼다. broad probing, weaponization,
persistence, secret dumping, privilege expansion을 중단하고, 최소한의
reproducibility, root-cause, affected-range, safety and disclosure evidence만
수집한다. 이후의 실험은 disclosure/ownership gate와 명시적 재개 조건 없이는
진행하지 않는다.

## Non-overlap and collaboration

현재 역할 분리는 고정한다. 실행 코드와 테스트의 구현·수정은 Luna Max
worker에게 위임한다. Root Codex는 다음 실험 선택, 가설·계약·위험·복구 설계,
worker 지휘, 구현 검토, 실기기 실행, evidence 판정, 문서 통합과 최종 commit을
소유한다. 별도 hostile-review agent는 구현자와 독립적으로 정확한 바이트를
검사한다. Root가 구현 결함을 발견하면 직접 코드 패치를 섞지 않고 Luna Max에
반환하며, root 판단과 독립 review가 모두 닫히기 전에는 live effect를 실행하지
않는다.

새 실험은 다른 worktree/agent와 다음 세 가지를 모두 검사해야 한다.

1. file intersection: owned files, generated artifacts, manifests, logs;
2. address/range intersection: VA/file/PA, device node, partition, memory range;
3. semantic-question collision: 같은 unknown, writer, ownership, bypass 또는
   runtime effect를 서로 다른 방법으로 동시에 mutate/measure하는지.

충돌하면 실행하지 말고 complementary evidence로 재설계한다. 기존 evidence는
재사용하되 target profile, device identity, approval state, rollback identity를
worktree/experiment 사이에 transfer하지 않는다.

## Definition of done

Iteration은 다음이 모두 기록되고 검증될 때만 complete다.

- exact current target, inputs, hashes, build/tool versions, timestamps,
  commands, repetitions와 retained log references;
- pure static/read-only iteration에 live repetitions, rollback, recovery 또는
  device binding처럼 genuinely inapplicable한 field가 있으면
  `NOT_APPLICABLE`과 명시적 reason을 기록한다. 해당 field를 silently omit하지
  않는다;
- explicit negative controls와 failure/stop result;
- deterministic public manifest, private/public separation, no raw bytes/secrets;
- focused tests와 diff/format checks. combined/full suite, public JSON parse,
  regeneration byte identity, publication mode는 위 checkpoint에 적용;
- primary verification과, 해당 checkpoint이면 independent hostile review의
  PASS 기록;
- clean atomic commit hash와 변경 파일 목록;
- 결과별 `PROVED/SUPPORTED/HYPOTHESIS/UNKNOWN/REFUTED`, residual unknowns,
  authority boundary와 next discriminator.

## Failure, retry and recovery

실패가 write effect를 포함할 가능성이 있으면 retry/replay하지 않는다. 먼저
durable journal, target re-enumeration, before/after hash, rollback/recovery,
health를 reconcile한다. Observer timeout은 effect 이후 recovery-pending이며
재전송 사유가 아니다. 같은 blocker가 반복되면 새로운 권한을 발명하지 말고
pause한다. 반복되는 동일 blocker와 의미 있는 progress 부재는 user/external
state change를 요구하는 상태로 notify한다.

## Loop termination

다음 중 하나면 loop를 종료한다.

- classification이 `CLASS C (TRANSFORM ONLY)`에서 변경됨;
- mandatory gate가 열려 외부 decision/disclosure/user action이 필요함;
- objective가 명시적으로 `PROVED` 또는 `REFUTED`됨;
- positive expected information value를 가진 안전한 non-overlapping experiment가
  더 이상 없음;
- user가 중지를 지시함.

종료 시에도 residual `UNKNOWN`, untouched devices/ranges, last clean commit,
재개에 필요한 조건을 보고한다.
