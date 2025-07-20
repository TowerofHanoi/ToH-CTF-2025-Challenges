# How to Deploy a Wii Pwn Challenge

Let’s suppose **Frank01001** finally achieved his lifelong dream: writing a CTF pwn challenge for the **Nintendo Wii**. It’s tested, it’s exploitable, and everything looks fantastic! However, there’s still one final thing to take care of: deployment.

It’s a pwn challenge, so you need to **remotely deploy it**.

---

## Step 1: Choose the Emulator

The best option here is the **Dolphin Emulator**. It’s the most famous and well-supported Nintendo Wii emulator, and we confirmed it has decent networking support (we tested this by launching the Homebrew Browser — it worked!).

---

## Step 2: Decide How to Provide Input

There are two types of input to handle:

- **Controller input**, since the challenge requires player interaction
- **SD card contents**, since the exploit is loaded from the SD card image

### Controller Input Options

We considered two approaches:

1. **Expose an X11 server** to each user so they could interact with the challenge remotely
2. Use Dolphin's **TAS (Tool-Assisted Speedrun)** feature to simulate the controller input

We chose the second option for two main reasons:

- It makes the interaction **deterministic and frame-perfect**
- It avoids latency and input issues caused by remote X11 setups

Luckily, Dolphin supports passing a TAS input file directly via CLI using the `-m` parameter. Nice!

### SD Card Input

Dolphin allows overriding any configuration from the command line. Using the following flag, we can specify a custom SD image:

```bash
--config=Dolphin.General.WiiSDCardPath=/path/to/sdcard.raw
```

## Step 3: Start Dolphin with CLI Parameters

We prepared the SD card with the exploit, recorded the TAS input, and tested it: the exploit triggered, and the flag was received. Beautiful. Time to automate it!

Here’s how we launched Dolphin:

```./dolphin-emu -e /forsaken_tower.elf -v=OGL --config=Dolphin.General.WiiSDCardPath=/sdcard.raw -m /tas.dtm```

We noticed something weird: when we run the challenge without the TAS input, the flag arrives as expected. But when we do pass the TAS script with -m, Dolphin runs, inputs are played, but... no flag. Uh oh.

## Step 4: Fix the TAS issue
After a bit of digging (and cursing), we found a suspicious bit of code in Socket.cpp. 

```cpp
// No Wii socket support while using NetPlay or TAS
#include "Core/IOS/Network/Socket.h"

#include <algorithm>
#include <numeric>
```

Apparently, the Dolphin developers consider networking to be a **non-deterministic source** during speedruns, and thus **disable it when TAS features are enabled**!

In other words, Dolphin deliberately disables networking when recording or playing back TAS input, to preserve determinism. Great for speedrunners — not so great for us.

While we briefly considered going back to the **X11 input solution**, we chose a different (and way cooler) path: **patching Dolphin to re-enable networking during TAS playback**!

After some reversing and spelunking through the codebase, we came up with the following patch:

```c
index e80e382930..e0bc77d942 100644
--- a/Source/Core/Core/Core.cpp
+++ b/Source/Core/Core/Core.cpp
@@ -217,6 +217,7 @@ bool IsHostThread()
 bool WantsDeterminism()
 {
   return s_wants_determinism;
+    // return false;
 }
 
 // This is called from the GUI thread. See the booting call schedule in
@@ -958,7 +959,7 @@ void UpdateWantDeterminism(Core::System& system, bool initial)
   // For now, this value is not itself configurable.  Instead, individual
   // settings that depend on it, such as GPU determinism mode. should have
   // override options for testing,
-  bool new_want_determinism = system.GetMovie().IsMovieActive() || NetPlay::IsNetPlayRunning();
+  bool new_want_determinism = /* system.GetMovie().IsMovieActive()  || */ NetPlay::IsNetPlayRunning();
   if (new_want_determinism != s_wants_determinism || initial)
   {
     NOTICE_LOG_FMT(COMMON, "Want determinism <- {}", new_want_determinism ? "true" : "false");
diff --git a/Source/Core/Core/IOS/IOS.cpp b/Source/Core/Core/IOS/IOS.cpp
index 7449ba69bb..1efe444407 100644
--- a/Source/Core/Core/IOS/IOS.cpp
+++ b/Source/Core/Core/IOS/IOS.cpp
@@ -856,8 +856,8 @@ void EmulationKernel::UpdateDevices()
 
 void EmulationKernel::UpdateWantDeterminism(const bool new_want_determinism)
 {
-  if (m_socket_manager)
-    m_socket_manager->UpdateWantDeterminism(new_want_determinism);
+//   if (m_socket_manager)
+//     m_socket_manager->UpdateWantDeterminism(new_want_determinism);
   for (const auto& device : m_device_map)
     device.second->UpdateWantDeterminism(new_want_determinism);
 }
diff --git a/Source/Core/Core/IOS/Network/IP/Top.cpp b/Source/Core/Core/IOS/Network/IP/Top.cpp
index 08008f97b7..52e8796138 100644
--- a/Source/Core/Core/IOS/Network/IP/Top.cpp
+++ b/Source/Core/Core/IOS/Network/IP/Top.cpp
@@ -459,10 +459,10 @@ static DefaultInterface GetSystemDefaultInterfaceOrFallback()
 
 std::optional<IPCReply> NetIPTopDevice::IOCtl(const IOCtlRequest& request)
 {
-  if (Core::WantsDeterminism())
-  {
-    return IPCReply(IPC_EACCES);
-  }
+//   if (Core::WantsDeterminism())
+//   {
+//     return IPCReply(IPC_EACCES);
+//   }
 
   switch (request.request)
   {
diff --git a/Source/Core/Core/IOS/Network/SSL.cpp b/Source/Core/Core/IOS/Network/SSL.cpp
index 36caab6305..789c6e3a9c 100644
--- a/Source/Core/Core/IOS/Network/SSL.cpp
+++ b/Source/Core/Core/IOS/Network/SSL.cpp
@@ -230,8 +230,8 @@ std::optional<IPCReply> NetSSLDevice::IOCtlV(const IOCtlVRequest& request)
 
   // I don't trust SSL to be deterministic, and this is never going to sync
   // as such (as opposed to forwarding IPC results or whatever), so -
-  if (Core::WantsDeterminism())
-    return IPCReply(IPC_EACCES);
+//   if (Core::WantsDeterminism())
+//     return IPCReply(IPC_EACCES);
 
   auto& system = Core::System::GetInstance();
   auto& memory = system.GetMemory();
diff --git a/Source/Core/Core/IOS/Network/Socket.cpp b/Source/Core/Core/IOS/Network/Socket.cpp
index bae1d48778..967cb297a7 100644
--- a/Source/Core/Core/IOS/Network/Socket.cpp
+++ b/Source/Core/Core/IOS/Network/Socket.cpp
@@ -1214,9 +1214,9 @@ void WiiSockMan::AddPollCommand(const PollCommand& cmd)
 
 void WiiSockMan::UpdateWantDeterminism(bool want)
 {
-  // If we switched into movie recording, kill existing sockets.
-  if (want)
-    Clean();
+//   // If we switched into movie recording, kill existing sockets.
+//   if (want)
+//     Clean();
 }
 
 void WiiSocket::Abort(WiiSocket::sockop* op, s32 value) const
```

Basically, we just **commented out three lines of code** that were responsible for disabling networking when TAS was enabled.

We rebuilt Dolphin, retested the setup, and... everything worked perfectly! 🎉

## Step 5: Provide a way to users for interact with the challenge

The final piece of the puzzle was allowing players to **upload their own SD card images and TAS input files**. For that, we built a simple **Python frontend** that spawns a Dolphin instance with the appropriate paths for the uploaded SD card and TAS input.

Smooth, clean, and fully automated!

This is our frontend, and this is the code we use to start a Dolphin instance 

![](frontend.png)

```py
def run_with_timeout(sdcard_path, tas_path, nand_path):  
    env = os.environ.copy()
    subprocess.Popen([
        "timeout", "--signal=SIGKILL", "60s",
        "/usr/local/bin/dolphin-emu", "-e", "/forsaken_tower.elf", 
        "-v=OGL", f"--config=Dolphin.General.WiiSDCardPath={sdcard_path}", 
        f"--config=Dolphin.General.NANDRootPath={nand_path}",
        '-m', tas_path
        ], env=env) 
```

At this point, we needed a way to avoid players uploading **512MB SD card images** just to send **two tiny files**. Not ideal.

The better idea we came up with was to have players **upload a ZIP file** containing their files. Then, on our side, we would **pack the SD card** just like you would with the *"Pack SD Card"* feature in Dolphin.

This piece of code does the trick:
```py
def make_sdcard_from_zip(zip_file_stream, output_path):
    with tempfile.TemporaryDirectory() as tmpdir:
        extract_path = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_path, exist_ok=True)

        safe_extract_zip(zip_file_stream, extract_path)

        subprocess.run(["dd", "if=/dev/zero", f"of={output_path}", "bs=1M", "count=512"], check=True)
        subprocess.run(["mkfs.vfat", "-F", "32", output_path], check=True)
        # Copy files to the SD card image
        for f in os.listdir(extract_path):
            subprocess.run(["mcopy", "-i", output_path, "-s", os.path.join(extract_path, f), "::/"], check=True)

def safe_extract_zip(zip_stream, extract_path):
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmpzip:
        tmpzip.write(zip_stream.read())
        tmpzip.flush()

    with zipfile.ZipFile(tmpzip.name, 'r') as zip_ref:
        for info in zip_ref.infolist():
            name = info.filename

            # Reject absolute paths
            if os.path.isabs(name):
                raise ValueError(f"Blocked absolute path in zip: {name}")

            # Reject path traversal
            if ".." in os.path.normpath(name).split(os.path.sep):
                raise ValueError(f"Blocked path traversal in zip: {name}")

            # Reject symlinks
            is_symlink = (info.external_attr >> 16) & 0o120000 == 0o120000
            if is_symlink:
                raise ValueError(f"Blocked symlink in zip: {name}")

            extracted_path = os.path.join(extract_path, name)
            if not extracted_path.startswith(os.path.abspath(extract_path)):
                raise ValueError(f"Blocked suspicious zip path: {name}")

        zip_ref.extractall(extract_path)

    os.unlink(tmpzip.name)  

```

The idea is to create a **blank 512MB disk image**, format it as **FAT32**, and then copy the user-provided files into it — just like a real SD card.

Once the SD card is ready, we create a **temporary working directory** for each Dolphin process. In that directory, we place the **Wii NAND**, the **SD card image**, and the **TAS script** — this ensures that each interaction is completely isolated.

At this point, everything seems complete.

**HOWEVER... IT’S STILL NOT WORKING!**

Why? Because of this:


```
qt.qpa.xcb: could not connect to display 
qt.qpa.plugin: Could not load the Qt platform plugin "xcb" in "" even though it was found.
This application failed to start because no Qt platform plugin could be initialized. Reinstalling the application may fix this problem.

Available platform plugins are: vnc, minimal, eglfs, xcb, vkkhrdisplay, linuxfb, wayland, minimalegl, offscreen, wayland-egl.

Aborted (core dumped)
```

Actually, Dolphin **requires an X11 server to connect to**!
We solved this by starting a **headless X11 server** with the following command:

```bash
#!/bin/bash
nohup Xvfb :99 -screen 0 1024x768x24 &
python3 /app/launcher.py
```
Simply launching Dolphin with the environment variable DISPLAY=:99 did the trick.

# Step 6: Containerize everything
During our tests, we noticed that **memory offsets inside the emulated Wii can vary** depending on the Dolphin build and its configuration.  
To avoid inconsistencies between local and remote exploits, we **containerized everything**, so players can use the **exact same setup** that runs on our servers.  
We also configured the infrastructure to **deploy a dedicated container instance per team**.

But we’ll talk more about that in a full **ToH CTF infrastructure deployment writeup**, coming soon™!

However, during containerization, we ran into a few more issues.

First, **Dolphin was crashing mysteriously** with a generic `SIGBUS` error. After some digging, we discovered that Dolphin uses an amount of **shared memory** for IPC, which is higher than the default size allowed by Docker. We fixed this by starting the container with the `--shm-size=2G` parameter.


Lastly, **Dolphin doesn’t automatically run the TAS input path on first launch**.  
We resolved this by **pre-copying the necessary config files** into the image in the `Dockerfile`.

Now everything runs smoothly — and reproducibly!


✅ **Now our deployment is fully complete!**

You can find the **entire deployment setup** in our repo!