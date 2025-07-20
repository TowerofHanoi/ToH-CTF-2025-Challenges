// @format
import React from "react";

import {
  theme,
  BorderList,
  Panel,
  Row
} from "./UIComponents";

let styles = {
  line: {
    fill: "none",
    stroke: theme.secondary,
    strokeWidth: 2
  },
  dndBox: {
    fill: "none",
    stroke: theme.white,
    strokeWidth: 0.1,
    height: 1,
    width: 1
  },
  dndBoxActive: {
    fill: theme.white
  },
  corners: {
    strokeWidth: 0.1,
    length: 1.5,
    stroke: theme.white
  }
};

export default class ControlBox extends React.Component {
  constructor(props) {
    super(props);
    
    this.handleStartRecording = this.handleStartRecording.bind(this);
    this.handleStopRecording = this.handleStopRecording.bind(this);
    this.handlePlayRecording = this.handlePlayRecording.bind(this);
  }

  handleStartRecording() {
    const {
      synth: { onStartRecording }
    } = this.props;
    onStartRecording();
  }

  handleStopRecording() {
    const {
      synth: { onStopRecording }
    } = this.props;
    onStopRecording();
  }

  handlePlayRecording() {
    const {
      synth: { onPlayRecording }
    } = this.props;
    onPlayRecording();
  }

  render() {
    return (
      <div>
        <Panel>
          <BorderList width="100%" directionRow justifyCenter>
            <button 
            onClick={this.handleStartRecording}
            style={{ padding: '5px 10px', background: theme.secondary, color: theme.black, border: 'none', borderRadius: '4px', marginRight: '5px' }}
            >
            Record
            </button>
            <button 
            onClick={this.handleStopRecording}
            style={{ padding: '5px 10px', background: theme.secondary, color: theme.black, border: 'none', borderRadius: '4px', marginRight: '5px' }}
            >
            Stop
            </button>
            <button 
            onClick={this.handlePlayRecording}
            className="btnPlay"
            style={{ padding: '5px 10px', background: theme.secondary, color: theme.black, border: 'none', borderRadius: '4px' }}
            >
            Play
            </button>
          </BorderList>
        </Panel>
        <div id="playStatus" style={{ textAlign: 'center', padding: '5px 10px', color: theme.white, border: 'none', borderRadius: '4px', marginLeft: '5px' }}>
          Welcome to ToH-Synth, a modified version of <a href="https://timdaub.github.io/wasm-synth/" target="_blank">WASM-Synth</a> where we've added recording and playback features for your compositions.<br/>These features are still under development :(
        </div>
      </div>
    );
  }
}
