import React, { useEffect, useRef } from 'react';

const levelColors = {
  E: 'text-red-400',
  W: 'text-yellow-400',
  I: 'text-blue-400',
  D: 'text-slate-400',
  V: 'text-slate-500',
};

function getLogLevel(line) {
  const match = line.match(/^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\d+\s+([EWDIV])\s/);
  if (match) return match[1];
  if (line.includes(' E ') || line.startsWith('E/')) return 'E';
  if (line.includes(' W ') || line.startsWith('W/')) return 'W';
  if (line.includes(' I ') || line.startsWith('I/')) return 'I';
  if (line.includes(' D ') || line.startsWith('D/')) return 'D';
  return 'V';
}

export default function LogcatStream({ lines = [], maxLines = 500 }) {
  const containerRef = useRef(null);
  const autoScrollRef = useRef(true);

  useEffect(() => {
    const el = containerRef.current;
    if (el && autoScrollRef.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [lines]);

  function handleScroll() {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    autoScrollRef.current = atBottom;
  }

  const displayLines = lines.slice(-maxLines);

  return (
    <div
      ref={containerRef}
      onScroll={handleScroll}
      className="bg-slate-900 rounded-lg p-3 font-mono text-xs overflow-y-auto h-full min-h-[200px]"
    >
      {displayLines.length === 0 ? (
        <span className="text-slate-500">Waiting for logcat output...</span>
      ) : (
        displayLines.map((line, i) => {
          const level = getLogLevel(line);
          return (
            <div key={i} className={`${levelColors[level] || 'text-slate-400'} leading-5 break-all`}>
              {line}
            </div>
          );
        })
      )}
    </div>
  );
}
