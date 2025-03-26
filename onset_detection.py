from madmom.features.onsets import OnsetPeakPickingProcessor, CNNOnsetProcessor

# Load an audio file (can be .wav or .mp3)
audio_file = r"C:\Users\jibin\OneDrive\Desktop\music_software\samplesong1.mp3"  # Updated path

# Detect onsets
onset_activations = CNNOnsetProcessor()(audio_file)
onsets = OnsetPeakPickingProcessor()(onset_activations)

print("Onsets:", onsets)