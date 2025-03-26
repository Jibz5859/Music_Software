from madmom.audio.chroma import ChromaProcessor

# Load an audio file (can be .wav or .mp3)
audio_file = r"C:\Users\jibin\OneDrive\Desktop\music_software\samplesong1.mp3"  # Updated path

# Compute chroma features
chroma = ChromaProcessor()(audio_file)

print("Chroma Features:", chroma)