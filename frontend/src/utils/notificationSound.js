let audioContext = null;

function getAudioContext() {
  const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextCtor) return null;
  if (!audioContext) audioContext = new AudioContextCtor();
  return audioContext;
}

export function initializeNotificationSound() {
  const ctx = getAudioContext();
  if (!ctx) return;
  if (ctx.state === 'suspended') {
    ctx.resume().catch(() => {});
  }
}

export function playCompletionSound(tone = 'success') {
  const ctx = getAudioContext();
  if (!ctx) return;

  const start = ctx.currentTime + 0.02;
  const master = ctx.createGain();
  master.gain.setValueAtTime(0.0001, start);
  master.gain.exponentialRampToValueAtTime(0.16, start + 0.03);
  master.gain.exponentialRampToValueAtTime(0.0001, start + 0.5);
  master.connect(ctx.destination);

  const frequencies = tone === 'error' ? [220, 174] : [523.25, 659.25, 783.99];

  frequencies.forEach((frequency, index) => {
    const oscillator = ctx.createOscillator();
    const gain = ctx.createGain();
    const noteStart = start + index * 0.12;
    const noteEnd = noteStart + 0.18;

    oscillator.type = 'sine';
    oscillator.frequency.setValueAtTime(frequency, noteStart);
    gain.gain.setValueAtTime(0.0001, noteStart);
    gain.gain.exponentialRampToValueAtTime(0.9, noteStart + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, noteEnd);

    oscillator.connect(gain);
    gain.connect(master);
    oscillator.start(noteStart);
    oscillator.stop(noteEnd + 0.02);
  });
}
