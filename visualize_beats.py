import matplotlib.pyplot as plt
from madmom.audio.signal import Signal
from madmom.features.beats import RNNBeatProcessor, DBNBeatTrackingProcessor
import librosa
import librosa.display
import numpy as np
from spleeter.separator import Separator

# Suppress TensorFlow warnings (optional)
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Set the custom model path using an environment variable
os.environ['SPLEETER_MODEL_PATH'] = r"C:\Users\jibin\OneDrive\Desktop\music_software\pretrained_models"

# Load the audio file
audio_file = r"C:\Users\jibin\OneDrive\Desktop\music_software\samplesong1.mp3"
signal = Signal(audio_file)

# Extract beats
beat_activations = RNNBeatProcessor()(audio_file)
beats = DBNBeatTrackingProcessor(fps=100)(beat_activations)

# Extract chroma features (for chord detection)
y, sr = librosa.load(audio_file)
chroma = librosa.feature.chroma_stft(y=y, sr=sr, hop_length=2048)  # Adjusted hop_length

# Function to map chroma features to chord labels
def extract_chords(chroma):
    chords = []
    for frame in chroma.T:
        # Find the pitch class with the highest energy
        chord_index = np.argmax(frame)
        # Map the index to a chord label
        chord_labels = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B']
        chords.append(chord_labels[chord_index])
    return chords

# Extract chords
chords = extract_chords(chroma)

# Print the detected chords
print("Detected Chords:", chords)

# Separate the audio file into stems using Spleeter
print("Separating audio file into stems...")
separator = Separator('spleeter:4stems')  # No need for model_directory parameter
separator.separate_to_file(audio_file, 'output_folder')
print("Instrument separation complete. Check the 'output_folder' for separated tracks.")

# Create a figure with two subplots
plt.figure(figsize=(12, 8))

# Plot the waveform with detected beats
plt.subplot(2, 1, 1)  # First subplot
plt.plot(signal)
plt.title("Waveform with Detected Beats")
plt.xlabel("Time (s)")
plt.ylabel("Amplitude")

# Plot the beats
for beat in beats:
    plt.axvline(x=beat, color='r', linestyle='--', alpha=0.7)

# Plot the chroma features
plt.subplot(2, 1, 2)  # Second subplot
librosa.display.specshow(chroma, y_axis='chroma', x_axis='time', hop_length=2048)  # Match hop_length
plt.colorbar()
plt.title('Chroma Features (Chord Detection)')

# Add chord labels to the plot
times = librosa.times_like(chroma, sr=sr, hop_length=2048)  # Updated with hop_length
for i, (time, chord) in enumerate(zip(times, chords)):
    if i % 5 == 0:  # Add a label every 5 frames to avoid clutter
        plt.text(time, -1, chord, color='white', fontsize=8, ha='center')

plt.tight_layout()

# Save the plot as an image
plt.savefig('waveform_and_chroma.png')

# Display the plot
plt.show()