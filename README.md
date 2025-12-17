# Moonwalk++ 

PoC Implementation combining Stack Moonwalking and Memory Encryption.

## TL;DR

Moonwalk++ is a PoC implementation of an enahnced version of [StackMoonwalk](https://github.com/klezVirus/SilentMoonwalk), which combines its original technique to remove the caller from the call stack, with a memory self-encryption routine, using ROP to both desynchronize unwinding from control flow and simultaneously encrypt the executing shellcode to hide it from inpection.

**Read more in the Blog Post:** [Malware Just Got Its Free Passes Back!](https://klezvirus.github.io/posts/Moonwalk-plus-plus/). 

## Is it Moonwalk++? (or minus minus --?)

GitHub will not allow the name to contain `+`, so well, it is named `--` but should have been `++`. Give or take, who cares?

## Overview

This repository demonstrates a PoC implementation to spoof the call stack when calling arbitrary Windows APIs, while simultanously encrypt the executing shellcode. 

An extensive overview of the technique and why it was developed can be read [here](https://klezvirus.github.io/posts/Moonwalk-plus-plus/).

This POC was made to work ONLY when injecting to `OneDrive.exe`. As such, in order to replicate its behaviour, you would need to ensure OneDrive is installed and running. Afterwards, retrieve one of the PID the program instantiates:

```powershell
(Get-Process OneDrive) | ForEach-Object {Write-Host $_.Id}
```

And provide the tool with one of them:

```bash
Moonwalk++ <PID-of-OneDrive>
```

### Injection

The POC is expecting a PID of `OneDrive.exe` to be provided as a CLI argument. The first frame is selected from the `OneDrive.exe` executable loaded from a well-defined location (i.e. `C:\Program Files\Microsoft OneDrive\OneDrive.exe`)

### OPSEC.. what?

This proof of concept has minimal operational security and is intentionally rough. Its primary purpose is to substantiate the theoretical claims discussed in the blog post [Malware Just Got Its Free Passes Back!](https://klezvirus.github.io/posts/Moonwalk-plus-plus/). 

## Execute

Careful when testing! The Loader will cause OneDrive to pop a MessageBox, but the popup may not be visible immediately, and if you keep going with the loader BEFORE cliclicking on the "OK" button of MessageBox, it will crash the process! The correct execution order is: 

1. Execute moonwalk (print first messages)
2. Check that all the gadgets have been correctly identified
3. Press Enter to Execute once
4. At this stage, an Icon in the TaskBar (OneDrive Directory) should have apepared, click on it, it will reveal the MessageBox popup
5. Click OK on the MessageBox so the Thread can return and execute the appropriate decryption chains
6. Now go back to the Moonwalk console and you can repeat the process

## Build

In order to build the POC and observe a similar behaviour to the one in the picture, ensure to:

* Disable GS (`/GS-`)
* Disable Code Optimisation (`/Od`)
* Disable Whole Program Optimisation (Remove `/GL`)
* Disable size and speed preference (Remove `/Os`, `/Ot`)
* **Enable** intrinsic if not enabled (`/Oi`)

## Previous Work and Credits

Check [SilentMoowalk#PreviousWork](https://github.com/klezVirus/SilentMoonwalk?tab=readme-ov-file#previous-work).

## Technical Notes (17/12/2025)

For this specific POC, I used some very, very specific gadget `wininet.dll` to bypass Eclipse. This gadget is not found in all builds and is version dependent. I extended the check to ensure that if there is a compatible gadget is going to be used.

In a similar way, the Big Stack Pivot gadget in KernelBase `ADD RSP, 0x1538`had a similar limitation. To make this more stable I updated the POC to dynamically search a general BIG pattern in multiple DLLs  and dynamically extract the size. Any size bigger than 0x500 bytes is considered fine by the POC.

Another bug I was notified about pertained to the `SetThreadContext` API. On certain machines, I had to use a non-volatile register to pass the references to the SPOOFER configuration while hijacking the thread context.

## Additional Notes

* This POC was made only to support and proof the feasibility to combine Stack Moonwalk and Memory Encryption. As the previous POC (SilentMoonwalk), it is not production ready and needs a lot of testing before integrating into C2 frameworks or similar. Use at your own risk.
* I'm not planning extensions for this technique, at least for now.
