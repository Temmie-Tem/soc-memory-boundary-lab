# SM8150 Architecture and Protection Map

This is a confidence map, not a completed block diagram.

```text
CPU virtual address
  -> ARMv8 MMU / stage-1 translation
  -> system physical address
  -> SM8150 interconnect path
  -> LLCC-facing / memory-controller-facing path
  -> DDRSS memory controller + PHY
  -> LPDDR4X channel/rank/bank/row/column
```

`PROVED`: The exact downstream DT represents a path from `MASTER_LLCC` to
`SLAVE_EBI_CH0` and a distinct `SLAVE_CNOC_DDRSS` configuration endpoint.
Evidence: exact source `sm8150-bus.dtsi:1091-1098` and `:1573-1581`, SHA-256
`2f72785b42496ff21ade9bc2ee5bfc06253daaf6352e1caf2683d0d8a06f4c4d`.

`PROVED`: The exact DT supplies LLCC at `0x09200000 + 0x450000`, four bank
offsets, and broadcast offset `0x400000`. Evidence: `sm8150.dtsi:1971-1999`,
SHA-256 `c0d42e66ddd5640e2dd7b65527c25fb617008d94a6a04062b9e1077f0eb63849`.

`PROVED`: The Linux LLCC driver fields at offsets `0x21000 + 8*n`,
`0x21004 + 8*n`, `0x21f00`, and `0x21f04` configure cache slice allocation,
ways/capacity and activation. They are not source evidence for PA-to-DRAM
channel/bank selection. Evidence: `drivers/soc/qcom/llcc-slice.c:30-57` and
`:318-350`.

`PROVED`: DT exposes LLCC/DDR performance observation landmarks:
`0x090cc000` LLCC PMU, CPU-to-LLCC BWMON at `0x090b6400/0x090b6300`, and
LLCC-to-DDR BWMON at `0x090cd000`; the last path is labeled LLCC to EBI_CH0.
Evidence: `sm8150.dtsi:992-1059`.

`PROVED`: The AOP drivers visible to Linux only send DDR performance/frequency
messages (`{class: ddr, perfmode: on}` and 300 MHz on halt/poweroff). They do not
expose address-map programming. Evidence:
`drivers/soc/qcom/aop_ddrss_cmds.c:24-61` and
`drivers/soc/qcom/aop_ddr_msgs.c:24-60`.

`PROVED`: Exact live XBL owns DDR initialization/training and loads board-specific
DCB data, while exact live AOP contains the runtime DDR manager. Evidence:
Experiment 004 hashes and `research/live-firmware-static-recon.md`.

`PROVED`: XBL maps `MCCC_MCCC_MSTR` at `0x090b0000–0x090b0fff` as an
uncacheable `NS_DEVICE` during boot. This is a firmware-backed register landmark,
not yet a final-decode register identification or proof of post-boot EL1 access.

`PROVED`: Exact XBL's DDR remapper selects a row by channel/rank mask and total
MiB, constructs two physical-region records, and sends them to
`/dev/icbcfg/boot`. DAL property `icbcfg_info` resolves to four register bases:
`0x09248080`, `0x092c8080`, `0x09348080`, and `0x093c8080`. Exact topology
labels each containing window `qhs_llcc`; the layout-1 writer touches 32-bit
offsets `0x00..0x58` in each instance. Evidence:
`evidence/manifests/006-xbl-memory-pipeline-inventory.json` and
`research/xbl-shrm-icbcfg-recon.md`.

`SUPPORTED`: This four-instance block owns system-PA region placement/remapping
during DDR bring-up. `UNKNOWN`: whether it also owns final channel/bank/row
hashing, or whether that finer decode occurs later in SHRM/MCCC/MC logic.

`PROVED`: The exact live TrustZone ELF contains the same `/dev/icbcfg/boot`
device hash and the same four-base/six-slot layout record. `SUPPORTED`: secure
firmware has configuration knowledge for this remapper. Runtime invocation,
lock ownership and enforcement ordering remain `UNKNOWN`.

`REFUTED`: Downstream `mc_virt-base = 0x09680000` is by itself an exact DDR
controller-register identification. In this tree the `fab_mc_virt` fabric uses
`bypass-qos-prg`, and upstream review describes `*_virt` register ranges as
arbitrary/unused by the interconnect driver. Evidence: `sm8150-bus.dtsi:15-35`,
`:452-461`; upstream discussion:
<https://lkml.iu.edu/hypermail/linux/kernel/2007.3/04458.html>.

## Protection pipeline

`PROVED`: Exact kernel `hyp_assign_phys()` turns the caller's physical base and
size into a scatter-gather entry and sends source VMIDs, destination VMIDs and
permissions through `hyp_assign_table()` to SCM service `MP`, command `0x16`.
Evidence: exact `drivers/soc/qcom/secure_buffer.c:227-269,279-385`, SHA-256
`c8cf938407ef3f54b688eb451742ccec7458259704a68b2b3e87ad699df8ed5f`.

`PROVED`: The kernel-side ownership API therefore names system physical ranges,
not DRAM row/bank coordinates.

`UNKNOWN`: Which secure-world hardware/firmware block enforces the assignment.
`UNKNOWN`: Whether that check sees an address before or after final DDR address
decoding. `UNKNOWN`: Whether a second XPU/MPU check exists after a mutable
transform. None of these follow merely from the SCM call signature.

`PROVED`: Exact source initializes RKP with physical/virtual kernel metadata and
invokes `uh_call(UH_APP_RKP, RKP_START, ...)`; `uh_call` reaches `smc #0`.
Evidence: `init/main.c:701-728,849-854`, `include/linux/rkp.h`,
`include/linux/uh.h`, and `arch/arm64/kernel/uh_entry.S`; exact `init/main.c`
SHA-256 `814d9dafdc49b73ae4fe5d5625a1a1c205b75a915889118761cd0a2aa6650409`.

`PROVED`: Exact defconfig retains `CONFIG_UH_RKP`, `CONFIG_RKP_KDP`,
`CONFIG_RKP_NS_PROT`, `CONFIG_RKP_DMAP_PROT`, `CONFIG_RKP_CFP_JOPP`, and
`CONFIG_RKP_CFP_ROPP`. Evidence:
`arch/arm64/configs/r3q_kor_single_defconfig:656-671`, SHA-256
`3d90a83d61a7a1873249642f7657c572e06f91a61bc3e5b737758f08ec765216`.

`PROVED`: Independently extracted stock kallsyms and exact rebuild System.map
both contain `uh_call`, `rkp_init_ns`, `hyp_assign_table`, `hyp_assign_phys`,
`qcom_scm_assign_mem`, `rkp_init_data`, and 31 CFP/JOPP/ROPP symbol matches.
Hashes: stock map
`9e6a1d6f322344e3d6fced7e6d29a254e1516cc5163bad8595388a9d0d02ec3a`;
rebuild map
`573d61f1d6fcefbe3f9b0b1ccb88dad92eeddbb449ad45baa26c22233c25bf74`.

`REFUTED`: The self-built kernel disabled all RKP/QHEE paths. The exact config,
source callsite and two symbol maps contradict that claim.

`PROVED`: The live `hyp` partition is the QHEE/hypervisor image: its ELF load
address and entry fall inside live `hyp_mem`, and its code/data identify the
hypervisor, ownership and kernel-protection paths.

`PROVED`: The live TrustZone image names BIMC, MEMNOC and LLCC-broadcast MPUs.
Their precise enablement and ordering remain `UNKNOWN`.

## Answers required for a bypass determination

| Question | Current answer |
|---|---|
| Which block owns the final mapping? | `PROVED`: qhs_llcc ICB windows own boot region remapping. Final channel/bank/row decode owner remains `UNKNOWN`. |
| Who programs it? | `PROVED`: XBL programs the region remapper through `icbcfg`; SHRM/MCCC/MC final-decode ownership remains `UNKNOWN`. AOP runtime DDR management is `PROVED`. |
| At what stage? | Region-remap programming during XBL DDR initialization before HLOS is `PROVED`; later mutability remains `UNKNOWN`. |
| Can EL1 observe it? | Current userland `/dev/mem` route is `REFUTED` by live `CONFIG_DEVMEM=n`; a narrow kernel-space read adapter remains `UNKNOWN`. |
| Can EL1 modify it? | `UNKNOWN`; XBL's writer is identified, but post-boot EL1 reachability/lock state is untested. |
| Does EL2/EL3 lock it? | `UNKNOWN`. |
| Is there a post-transform security check? | `UNKNOWN`. |
