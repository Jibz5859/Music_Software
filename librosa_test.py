import librosa

# Load an audio file
audio_file = r"C:\Users\jibin\OneDrive\Desktop\music_software\samplesong1.mp3"
y, sr = librosa.load(audio_file)

# Print the sample rate and duration
print("Sample Rate:", sr)
print("Duration (seconds):", len(y) / sr)