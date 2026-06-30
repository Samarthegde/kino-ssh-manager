import { useEffect, useRef, useState } from "react";
import * as AsciinemaPlayer from "asciinema-player";
import "asciinema-player/dist/bundle/asciinema-player.css";
import { useVaultStore } from "../store";

interface ReplayModalProps {
  filename: string;
  onClose: () => void;
}

export function ReplayModal({ filename, onClose }: ReplayModalProps) {
  const { readRecording } = useVaultStore();
  const playerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let player: any = null;

    async function loadRecording() {
      try {
        const castData = await readRecording(filename);

        if (playerRef.current) {
          player = AsciinemaPlayer.create({ data: castData }, playerRef.current, {
            fit: "both",
            preload: true,
            theme: "tango",
          });
        }
      } catch (err) {
        setError(String(err));
      }
    }

    loadRecording();

    return () => {
      if (player) {
        player.dispose();
      }
    };
  }, [filename, readRecording]);

  return (
    <div className="modal-overlay">
      <div className="modal docker-modal">
        <div className="modal-header">
          <h2>Replay Session: {filename}</h2>
          <button className="icon-btn" onClick={onClose} title="Close">
            ✕
          </button>
        </div>
        <div
          className="modal-body"
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            minHeight: 0,
            background: "#000",
            padding: 0,
            overflow: "hidden",
          }}
        >
          {error ? (
            <div style={{ color: "var(--red)", padding: 20 }}>
              Failed to load recording: {error}
            </div>
          ) : (
            <div
              ref={playerRef}
              style={{
                width: "100%",
                height: "100%",
                display: "flex",
                flexDirection: "column",
              }}
            />
          )}
        </div>
      </div>
    </div>
  );
}
