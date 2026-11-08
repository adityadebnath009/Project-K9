'use client';

import React, { useRef, useState, useEffect, useCallback } from 'react';
import { Camera, CameraOff, RefreshCw, AlertCircle, Sparkles, Check, ScanLine } from 'lucide-react';

interface CameraScannerProps {
  onCapture: (blobOrDataUrl: string) => Promise<void>;
  isScanning: boolean;
}

export const CameraScanner: React.FC<CameraScannerProps> = ({ onCapture, isScanning }) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [isCameraActive, setIsCameraActive] = useState<boolean>(false);
  const [facingMode, setFacingMode] = useState<'environment' | 'user'>('environment');
  const [autoScanEnabled, setAutoScanEnabled] = useState<boolean>(true);

  // Start Camera Stream
  const startCamera = useCallback(async () => {
    setCameraError(null);
    try {
      if (stream) {
        stream.getTracks().forEach((t) => t.stop());
      }

      if (typeof navigator === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
        setCameraError('Camera API is not supported by your browser.');
        return;
      }

      const newStream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: facingMode },
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
        audio: false,
      });

      setStream(newStream);
      setIsCameraActive(true);

      if (videoRef.current) {
        videoRef.current.srcObject = newStream;
        await videoRef.current.play().catch(() => {});
      }
    } catch (err: any) {
      console.warn('Camera stream error:', err);
      if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
        setCameraError('Camera access was denied. Please allow camera permissions in your browser or switch to image file upload.');
      } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
        setCameraError('No camera found on this device. Please use image file upload mode.');
      } else {
        setCameraError(`Unable to start camera: ${err.message || 'Unknown error'}. Please use image file upload.`);
      }
      setIsCameraActive(false);
    }
  }, [facingMode]);

  // Stop Camera Stream
  const stopCamera = useCallback(() => {
    if (stream) {
      stream.getTracks().forEach((track) => track.stop());
      setStream(null);
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setIsCameraActive(false);
  }, [stream]);

  // Cleanup on unmount
  useEffect(() => {
    startCamera();
    return () => {
      if (stream) {
        stream.getTracks().forEach((track) => track.stop());
      }
    };
  }, []);

  // Capture frame to dataURL
  const captureFrame = useCallback(async () => {
    if (!videoRef.current || !canvasRef.current || isScanning) return;
    const video = videoRef.current;
    const canvas = canvasRef.current;

    if (video.videoWidth === 0 || video.videoHeight === 0) return;

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const dataUrl = canvas.toDataURL('image/jpeg', 0.85);

    try {
      await onCapture(dataUrl);
    } catch (err) {
      console.warn('Scan capture error:', err);
    }
  }, [onCapture, isScanning]);

  // Flip Camera
  const toggleFacingMode = () => {
    setFacingMode((prev) => (prev === 'environment' ? 'user' : 'environment'));
  };

  return (
    <div className="relative w-full rounded-2xl border border-zinc-800 bg-zinc-950/80 overflow-hidden shadow-2xl flex flex-col items-center justify-center p-4">
      {/* Hidden processing canvas */}
      <canvas ref={canvasRef} className="hidden" />

      {/* Camera Viewport Container */}
      <div className="relative w-full aspect-video sm:aspect-[4/3] max-w-lg rounded-xl overflow-hidden bg-black border border-zinc-800 flex items-center justify-center">
        {/* Live Video Feed */}
        <video
          ref={videoRef}
          autoPlay
          playsInline
          muted
          className={`w-full h-full object-cover ${!isCameraActive ? 'hidden' : ''}`}
        />

        {/* Optical Scanning HUD Overlay */}
        {isCameraActive && (
          <div className="absolute inset-0 pointer-events-none flex flex-col items-center justify-center">
            {/* Darkened outer vignette */}
            <div className="absolute inset-0 bg-black/30" />

            {/* Scanning Reticle Box */}
            <div className="relative w-48 h-48 sm:w-60 sm:h-60 border-2 border-sky-400/80 rounded-2xl shadow-[0_0_20px_rgba(56,189,248,0.25)] flex items-center justify-center">
              {/* Corner brackets */}
              <div className="absolute -top-1 -left-1 w-5 h-5 border-t-4 border-l-4 border-sky-400 rounded-tl-lg" />
              <div className="absolute -top-1 -right-1 w-5 h-5 border-t-4 border-r-4 border-sky-400 rounded-tr-lg" />
              <div className="absolute -bottom-1 -left-1 w-5 h-5 border-b-4 border-l-4 border-sky-400 rounded-bl-lg" />
              <div className="absolute -bottom-1 -right-1 w-5 h-5 border-b-4 border-r-4 border-sky-400 rounded-br-lg" />

              {/* Animated Laser Scanning Line */}
              <div className="absolute inset-x-2 h-0.5 bg-gradient-to-r from-transparent via-sky-400 to-transparent animate-pulse shadow-[0_0_8px_#38bdf8]" />

              <span className="text-[10px] font-mono text-sky-300/80 uppercase tracking-wider absolute -bottom-6">
                Point at physical QR Code
              </span>
            </div>
          </div>
        )}

        {/* Error / Off State */}
        {!isCameraActive && (
          <div className="p-6 text-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-zinc-900 border border-zinc-800 flex items-center justify-center mx-auto text-zinc-500">
              <CameraOff className="w-6 h-6" />
            </div>
            {cameraError ? (
              <div className="text-xs text-rose-300 max-w-sm leading-relaxed font-sans">
                {cameraError}
              </div>
            ) : (
              <p className="text-xs text-zinc-400">
                Camera is currently stopped. Click below to start live stream.
              </p>
            )}
            <button
              type="button"
              onClick={startCamera}
              className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-zinc-950 font-semibold text-xs transition-colors inline-flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Camera Stream</span>
            </button>
          </div>
        )}
      </div>

      {/* Camera Controls Bar */}
      <div className="w-full max-w-lg mt-4 flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          {isCameraActive ? (
            <button
              type="button"
              onClick={stopCamera}
              className="px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs font-mono transition-colors flex items-center gap-1.5"
            >
              <CameraOff className="w-3.5 h-3.5 text-rose-400" />
              <span>Stop Stream</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={startCamera}
              className="px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs font-mono transition-colors flex items-center gap-1.5"
            >
              <Camera className="w-3.5 h-3.5 text-sky-400" />
              <span>Start Stream</span>
            </button>
          )}

          <button
            type="button"
            onClick={toggleFacingMode}
            className="px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5 text-zinc-400" />
            <span>Flip ({facingMode === 'environment' ? 'Back' : 'Front'})</span>
          </button>
        </div>

        {/* Primary Snap Action */}
        <button
          type="button"
          disabled={!isCameraActive || isScanning}
          onClick={captureFrame}
          className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-zinc-950 font-semibold text-xs tracking-tight transition-all disabled:opacity-50 flex items-center gap-1.5 shadow-md shadow-sky-950/40"
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Analyzing Frame...</span>
            </>
          ) : (
            <>
              <ScanLine className="w-3.5 h-3.5" />
              <span>Snap &amp; Audit QR</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
