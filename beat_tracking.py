from madmom.features.beats import RNNBeatProcessor, BeatTrackingProcessor

# Path to your audio file
audio_file = "samplesong1.mp3"

# Step 1: Extract beat activations using a pre-trained neural network
beat_processor = RNNBeatProcessor()
beat_activations = beat_processor(audio_file)

# Step 2: Track beats from the activations
beat_tracker = BeatTrackingProcessor(fps=100)  # fps = frames per second
beats = beat_tracker(beat_activations)

# Print the beat timestamps (in seconds)
print("Beat timestamps (in seconds):", beats)