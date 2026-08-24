# A90 TWRP Code-Only System Boot

State: `PROVED` on the exact SM-A908N TWRP 3.7.0_12-0 used by this lab.

## Why ordinary CLI reboot failed

- `PROVED`: `twrp reboot` reached the OpenRecoveryScript parser, then the
  Recovery process crashed/restarted without rebooting the device.
- `PROVED`: direct `/system/bin/reboot` and `/system/bin/reboot system` rebooted
  the device but returned to Recovery.
- `PROVED`: `/system/bin/rebootsystem.sh` only zeroes the first 256 bytes of
  `/dev/block/by-name/misc`; that prefix was already all zero in the failed
  direct-reboot tests.

The exact theme at `/twres/portrait.xml` routes System through
`reboot_system_routine`, sets `tw_action_param=system`, and eventually invokes
the GUI `reboot` action. Upstream TeamWin source commit
`5c3d206a5eeb3d446bcda8248a405a4b278bab5c` shows that `GUIAction::reboot`
sets `tw_gui_done=1` and `tw_reboot_arg`; the Recovery main thread then calls
`TWFunc::tw_reboot` after GUI teardown. Exact-device strings independently
contain `/system/bin/rebootsystem.sh` and `reboot system`.

## Working transition

```text
twrp set tw_reboot_arg system
twrp get tw_reboot_arg        # must return exactly: tw_reboot_arg = system
sync; twrp set tw_gui_done 1  # one effect dispatch, never auto-retry
```

`PROVED`: this path booted native three times: from the no-load control, from
the one-load read candidate, and after the final V2321 rollback. It uses no
touch coordinates.

The fail-closed host implementation is
`tools/a90_twrp_system_boot.py`. It binds the Recovery endpoint by hashed
serial, `SM-A908N`, `r3q`, and TWRP version before setting the two variables.
It never invokes `twrp reboot` and does not retry an ambiguous effect.

## Claim boundary

This is a target-specific Recovery control result. It does not imply that the
same variables, TWRP behavior, or Samsung boot-selection state apply to another
model or Recovery build.
