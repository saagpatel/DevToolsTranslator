import React from 'react';

export function Chevron(): React.JSX.Element {
  return <svg viewBox="0 0 16 16" aria-hidden="true"><path d="m5 6 3 3 3-3" /></svg>;
}

export function Search(): React.JSX.Element {
  return <svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.5" /><path d="m10.5 10.5 3 3" /></svg>;
}

export function Warning(): React.JSX.Element {
  return <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2 14 13H2Z" /><path d="M8 5.5v3.5M8 11.5v.1" /></svg>;
}
