from madmom.features.beats import RNNBeatProcessor, DBNBeatTrackingProcessor

# Load an audio file
audio_file = r"C:\Users\jibin\OneDrive\Desktop\music_software\samplesong1.mp3"

# Extract beats
beat_activations = RNNBeatProcessor()(audio_file)
beats = DBNBeatTrackingProcessor(fps=100)(beat_activations)

print("Beats:", beats)