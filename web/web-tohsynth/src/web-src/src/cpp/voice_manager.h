#pragma once
#include <vector>
#include <map>
#include <cstdint>
#include "voice.h"
#include "oscillator.h"

class Voice;
struct EnvelopePreset;
struct Key {
  uint8_t keyValue;
  uint8_t offset;
};

using namespace std;

typedef vector<Voice*> Voices;
typedef vector<Key> Keys;

class VoiceManager {
private:
  int numOfVoices, sampleRate, numOfOscillators, recordedKeys;
  bool isRecording;
  Voices voices;
  Keys keys;
  int offset;
  Voice * FindFreeVoice();
  map<int, EnvelopePreset> envelopes;
  map<int, float> levels;
  void SetEnvelope(int i);
  void SetAllEnvelopes();
  void SetLevel(int i);
  void SetAllLevels();
  void AddKey(uint8_t key);
  void Notification(const char *message, bool showKeys = false);

public:
  VoiceManager(int sampleRate, int numOfVoices, int numOfOscillators);
	void OnNoteOn(int key);
	void OnNoteOff(int key);
  vector<float> NextSample(int bufferSize);
  void UpdateLevel(int i, float value);
  void UpdateEnvelope(int i, float xa, float xd, float ys, float xr, float ya);
  void UpdateWaveForm(int i, int w);
  void EnableOscillator(int i, bool b);
  void StartRecording();
  void StopRecording();
  std::string PlayRecording();
  void SetSynthData(uint8_t key, int8_t offset);
};
