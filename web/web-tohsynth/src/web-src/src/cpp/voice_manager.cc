#include "voice_manager.h"
#include <emscripten.h>

#define MAX_RECORDED_KEYS 128

VoiceManager::VoiceManager(int sampleRate, int numOfVoices,
                           int numOfOscillators) : voices() {
  this->sampleRate = sampleRate;
  this->numOfVoices = numOfVoices;
  this->numOfOscillators = numOfOscillators;
  this->voices.reserve(this->numOfVoices);
  this->recordedKeys = 0;
  this->isRecording = false;
  this->offset = 28;
  for (int i = 0; i < this->numOfVoices; i++) {
    this->voices.push_back(new Voice(sampleRate, this->numOfOscillators));
  }
}

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

void VoiceManager::SetEnvelope(int i) {
  for (Voices::iterator it = this->voices.begin(); it != this->voices.end(); ++it) {
    Voice *v = *it;
    if (v->isActive) {
      v->SetEnvelope(i, envelopes[i]);
    }
  }
}

void VoiceManager::SetAllEnvelopes() {
  for (int i = 0; i < numOfOscillators; ++i) {
    SetEnvelope(i);
  }
}

void VoiceManager::OnNoteOn(int key) {
  Voice *v = FindFreeVoice();
  v->key = key;
  v->iteration = 0;
  v->isActive = true;
  SetAllEnvelopes();
  SetAllLevels();
  v->SetStage(ADSRModulator::ENVELOPE_STAGE_ATTACK);
  if(this->isRecording) this->AddKey(key);
}

void VoiceManager::OnNoteOff(int key) {
  for (Voices::iterator it = this->voices.begin(); it != this->voices.end(); ++it) {
    Voice *v = *it;
    if (v->key == key && v->isActive) {
      v->SetStage(ADSRModulator::ENVELOPE_STAGE_RELEASE);
    }
  }
}

Voice * VoiceManager::FindFreeVoice() {
  for (Voices::iterator it = this->voices.begin(); it != this->voices.end(); ++it) {
    Voice *v = *it;
    if (!v->isActive) {
      return v;
    }
  }
  return NULL;
}

vector<float> VoiceManager::NextSample(int bufferSize) {
  vector<float> sample(bufferSize, 0.0f);
  for (Voices::iterator it = this->voices.begin(); it != this->voices.end(); ++it) {
    Voice *v = *it;
  
    if (v->isActive) {
      vector<float> voiceSample = v->NextSample(bufferSize);
        for (int i = 0; i < bufferSize; i++) {
          // TODO: Make total gain a UI element
          sample[i] += voiceSample[i] * 0.1;
        }
    }
  }

  return sample;
}

void VoiceManager::UpdateLevel(int i, float value) {
  levels[i] = value;
  SetLevel(i);
}

void VoiceManager::SetLevel(int i) {
  for (Voices::iterator it = this->voices.begin(); it != this->voices.end(); ++it) {
    Voice *v = *it;
    if (v->isActive) {
      v->SetLevel(i, levels[i]);
    }
  }
}

void VoiceManager::SetAllLevels() {
  for (int i = 0; i < numOfOscillators; ++i) {
    SetLevel(i);
  }
}

void VoiceManager::UpdateWaveForm(int i, int w) {
  Oscillator::WaveForm wCast = static_cast<Oscillator::WaveForm>(w);
  for (Voices::iterator it = this->voices.begin(); it != this->voices.end(); ++it) {
    Voice *v = *it;
    v->SetWaveForm(i, wCast);
  }
}

void VoiceManager::AddKey(uint8_t key) {
  if (this->recordedKeys >= MAX_RECORDED_KEYS && !this->isRecording) return;
  Key newKey;
  newKey.keyValue = key;
  newKey.offset = this->offset;
  this->keys.push_back(newKey);
  this->recordedKeys++;
}

void VoiceManager::Notification(const char *message, bool showKeys) {
  EM_ASM({
    console.info("Notification:", UTF8ToString($0));
  }, message);
}

void VoiceManager::StartRecording() {
  if(this->isRecording) return;
  this->recordedKeys = 0;
  this->keys.clear();
  this->isRecording = true;
  const char *notificationText = "Recording started! Press keys to record your song and/or change the envelope if you need. Press 'Stop Recording' when you are done.";
  this->Notification(notificationText);
}

void VoiceManager::StopRecording() {
  if(!this->isRecording) return;
  this->isRecording = false;
  const char *notificationText = "Your beautiful song is ready to be played again!";
  this->Notification(notificationText);
}

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
  strncpy(loading, songBytes, this->recordedKeys);
  if (!eventLog.empty() && eventLog.back() == ',') {
    eventLog.pop_back();
  }
  return std::string(lyrics + eventLog);
}

void VoiceManager::SetSynthData(uint8_t key, int8_t offset) {
  if ((offset < -27 || offset > 28) || (key < 60 || key > 95)) {
    EM_ASM({
      console.error(`Invalid offset value: ${$0}. It should be between -27 and 28.`);
    }, offset);
    return;
  }
  this->offset = offset;
  this->AddKey(key);
}

void VoiceManager::EnableOscillator(int i, bool b) {
  for (Voices::iterator it = this->voices.begin(); it != this->voices.end(); ++it) {
    Voice *v = *it;
    v->EnableOscillator(i, b);
  }
}

#include <emscripten/bind.h>
EMSCRIPTEN_BINDINGS(VoiceManager) {
  emscripten::class_<VoiceManager>("VoiceManager")
    .constructor<int, int, int>()
    .function("onNoteOn", &VoiceManager::OnNoteOn)
    .function("onNoteOff", &VoiceManager::OnNoteOff)
    .function("nextSample", &VoiceManager::NextSample)
    .function("updateLevel", &VoiceManager::UpdateLevel)
    .function("updateEnvelope", &VoiceManager::UpdateEnvelope)
    .function("updateWaveForm", &VoiceManager::UpdateWaveForm)
    .function("onStartRecording", &VoiceManager::StartRecording)
    .function("onStopRecording", &VoiceManager::StopRecording)
    .function("onPlayRecording", &VoiceManager::PlayRecording)
    .function("onSetSynthData", &VoiceManager::SetSynthData)
    .function("enableOscillator", &VoiceManager::EnableOscillator);
  emscripten::register_vector<float>("vector<float>");
}
