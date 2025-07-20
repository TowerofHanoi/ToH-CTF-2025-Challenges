// @format
import { AudioContext, AudioWorkletNode } from "standardized-audio-context";

export default class SynthAdapter {
  constructor(path, moduleId, envelope) {
    this.path = path;
    this.moduleId = moduleId;

    if (
      envelope &&
      typeof envelope.xa === "number" &&
      typeof envelope.xd === "number" &&
      typeof envelope.ys === "number" &&
      typeof envelope.xr === "number"
    ) {
      this.envelope = envelope;
    } else if (!envelope) {
      this.envelope = {
        xa: 0,
        xd: 0,
        ys: 1,
        xr: 0.5,
        ya: 1
      };
    } else {
      throw new Error(
        "Parameter 'envelope' need values of type 'number': xa, xd, ys, xr"
      );
    }

    this.worklet = null;
    this.context = null;
    this.setSynthData = false;

    this.onEnvelopeChange = this.onEnvelopeChange.bind(this);
    this.onNoteOn = this.onNoteOn.bind(this);
    this.onNoteOff = this.onNoteOff.bind(this);
    this.onLevelChange = this.onLevelChange.bind(this);
    this.onWaveFormChange = this.onWaveFormChange.bind(this);
    this.onEnableOscillator = this.onEnableOscillator.bind(this);
    this.onStartRecording = this.onStartRecording.bind(this);
    this.onStopRecording = this.onStopRecording.bind(this);
    this.onPlayRecording = this.onPlayRecording.bind(this);
  }

  async init() {
    if (!this.context) {
      this.context = new AudioContext();
      await this.context.audioWorklet.addModule(this.path);
      this.worklet = new AudioWorkletNode(this.context, this.moduleId, { outputChannelCount: [1] });
      this.worklet.connect(this.context.destination);

      // TODO: We assume 4 oscillators here, but actually we should define
      // them in a constants file
      for (let i = 0; i < 4; i++) {
        this.onEnvelopeChange(i)(this.envelope);
        // TODO: Constant
        this.onLevelChange(i)(0.25);
      }
    }

    if (this.context.state !== "running" && this.worklet) {
      await this.context.resume();
    }

    this.onSetSynthData();

    this.worklet.port.onmessage = event => {
      if(event.data.name === "PlayRecord") {
        if (event.data.values.recording && event.data.values.recording.includes("|")) {
          document.getElementById("playStatus").innerHTML = event.data.values.recording.split("|")[0];
          const urlParams = new URLSearchParams(window.location.search)
          if(!urlParams.has('synthdata') && confirm("What a wonderful recording! Do you want to download it?")) {
            const recordingData = event.data.values.recording.split("|")[1];
            const base64EncodedData = btoa(recordingData);
            const blob = new Blob([base64EncodedData], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'recording.synth';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          }
        }
      }
    };

    // NOTE: On the first note, we launch the audioContext but want to trigger
    // a note right afterwards in Piano.playNote. Hence we return true here only
    // once the context is running and the worklet has been loaded.
    return this.context.state === "running" && this.worklet;
  }

  async onNoteOn(key) {
    await this.init();

    this.worklet.port.postMessage({
      name: "NoteOn",
      key
    });
  }

  onNoteOff(key) {
    this.worklet.port.postMessage({
      name: "NoteOff",
      key
    });
  }

  onLevelChange(index) {
    return async value => {
      if (!(await this.init())) return;
      this.worklet.port.postMessage({
        name: "Level",
        values: {
          index,
          value
        }
      });
    };
  }

  // TODO: Can this be refactored to a simpler function (with two arguments)?
  onEnvelopeChange(index) {
    return async values => {
      if (!(await this.init())) return;
      this.worklet.port.postMessage({
        name: "Envelope",
        values: Object.assign({ index }, this.calcEnvelopeMapping(values))
      });
    };
  }
  
  onSetSynthData(){
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('synthdata') && !this.setSynthData) {
      try {
        const decodedData = atob(urlParams.get('synthdata'));
        var synthData = decodedData.match(/\((\d+),(-?\d+)\)/g)?.map(pair => {
          const [, key, offset] = pair.match(/\((\d+),(-?\d+)\)/);
          return {
            key: parseInt(key, 10),
            offset: parseInt(offset, 10)
          };
        }) || [];
        
        this.worklet.port.postMessage({
          name: "SetSynthData",
          values: {
            data: synthData
          }
        });
        
        this.setSynthData = true;
      } catch (error) {
        console.error("Failed to decode synthdata:", error);
      }
    }
  }

  async onWaveFormChange(index, value) {
    if (!(await this.init())) return;
    this.worklet.port.postMessage({
      name: "WaveForm",
      values: {
        index,
        value
      }
    });
  }

  async onEnableOscillator(index, value) {
    if (!(await this.init())) return;
    this.worklet.port.postMessage({
      name: "Enable",
      values: {
        index,
        value
      }
    });
  }

  async onStartRecording() {
    if (!(await this.init())) return;
    this.worklet.port.postMessage({
      name: "StartRecording"
    });
  }

  async onStopRecording() {
    if (!(await this.init())) return;
    this.worklet.port.postMessage({
      name: "StopRecording"
    });
  }

  async onPlayRecording() {
    if (!(await this.init())) return;

    this.worklet.port.postMessage({
      name: "PlayRecording"
    });
  }

  calcEnvelopeMapping(values) {
    // TODO: Put into constants file
    const microseconds = 1000 * 1000;

    const xa = Math.round(Math.exp(Math.log(20 * microseconds) * values.xa));
    const xd = Math.round(Math.exp(Math.log(60 * microseconds) * values.xd));
    const xr = Math.round(Math.exp(Math.log(60 * microseconds) * values.xr));

    return {
      xa,
      xd,
      xr,
      ya: values.ya,
      ys: values.ys
    };
  }
}
