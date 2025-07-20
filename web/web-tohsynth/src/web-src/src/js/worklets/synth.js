//@format

class SynthWorklet extends AudioWorkletProcessor {
  constructor() {
    super();
    this.kernel = Module();
    const numOfVoices = 64;
    const numOfOscillators = 4;
    this.voiceManager = new this.kernel.VoiceManager(
      sampleRate,
      numOfVoices,
      numOfOscillators
    );

    this.port.onmessage = this.handleEvents.bind(this);
  }

  handleEvents({ data }) {
    if (data.name === "NoteOn") {
      console.log("NoteOn event:", data);
      this.voiceManager.onNoteOn(data.key);
    } else if (data.name === "NoteOff") {
      console.log("NoteOff event:", data);
      this.voiceManager.onNoteOff(data.key);
    } else if (data.name === "Envelope") {
      console.log("Envelope Event:", data.values);
      const { index, xa, xd, ys, xr, ya } = data.values;
      this.voiceManager.updateEnvelope(index, xa, xd, ys, xr, ya);
    } else if (data.name === "Level") {
      console.log("Level Event:", data.values);
      const { index, value } = data.values;
      this.voiceManager.updateLevel(index, value);
    } else if (data.name === "WaveForm") {
      console.log("WaveForm Event:", data.values);
      const { index, value } = data.values;
      this.voiceManager.updateWaveForm(index, value);
    } else if (data.name === "Enable") {
      console.log("Enable Event:", data.values);
      const { index, value } = data.values;
      this.voiceManager.enableOscillator(index, value);
    } else if (data.name === "StartRecording") {
      console.log("StartRecording Event");
      this.voiceManager.onStartRecording();
    } else if (data.name === "StopRecording") {
      console.log("StopRecording Event");
      this.voiceManager.onStopRecording();
    } else if (data.name === "PlayRecording") {
      console.log("PlayRecording Event");
      this.port.postMessage({
        name: "PlayRecord",
        values: {
          recording: this.voiceManager.onPlayRecording()
        }
      });
    } else if (data.name === "SetSynthData") {
      console.log("SetSynthData Event:", data.values);
      for(var i = 0; i < data.values.data.length; i++){
        this.voiceManager.onSetSynthData(data.values.data[i].key, data.values.data[i].offset);
      }
    } else {
      console.warn("Unknown event received:", data);
    }
  }

  process(inputs, outputs, parameters) {
    // NOTE: We only use a single channel to generate our sounds, will be up-mixed to stereo.
    const outputChannel = outputs[0][0];
    const sample = this.voiceManager.nextSample(outputChannel.length);
    for (let i = 0; i < sample.size(); i++) {
      outputChannel[i] = sample.get(i);
    }

    return true;
  }
}

registerProcessor("SynthWorklet", SynthWorklet);