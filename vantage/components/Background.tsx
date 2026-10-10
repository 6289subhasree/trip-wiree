// Local animated backdrop: drifting red and blue glows drawn in CSS. No video, no network.
export function Background() {
  return (
    <div className="background" aria-hidden="true">
      <span className="glow glow-blue" />
      <span className="glow glow-violet" />
      <span className="glow glow-red" />
      <span className="wire" />
    </div>
  );
}
