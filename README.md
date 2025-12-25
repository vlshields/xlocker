# Locker

A very minimal screen locker for X11. 

### About

Locker, as its very original name would suggest, simply locks your display. It does nothing more and nothing less.

It uses Odin's lpam linker so that the user's password is automatically and safely configured.

It is still in the pre alpha phase.

### Building

```bash
odin build locker.odin -file -out:locker -extra-linker-flags:"-lpam" 2>&1
```
You can change -out: to whatever you want
