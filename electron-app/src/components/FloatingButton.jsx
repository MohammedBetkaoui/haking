import React, { useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { useStore } from '../store';

export default function FloatingButton({ expanded }) {
  const { expand, collapse, clearDetections, newDetectionCount, latestDetectedIp } = useStore();
  const [dragging, setDragging] = useState(false);
  const dragRef = useRef({
    active: false,
    moved: false,
    offsetX: 0,
    offsetY: 0,
    startScreenX: 0,
    startScreenY: 0,
    pointerId: null,
  });
  const suppressClickRef = useRef(false);

  const handlePointerDown = (event) => {
    if (expanded || !window.guardian?.move) return;

    dragRef.current = {
      active: true,
      moved: false,
      offsetX: event.clientX,
      offsetY: event.clientY,
      startScreenX: event.screenX,
      startScreenY: event.screenY,
      pointerId: event.pointerId,
    };

    suppressClickRef.current = false;
    setDragging(true);
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const handlePointerMove = (event) => {
    const state = dragRef.current;
    if (!state.active || expanded || !window.guardian?.move) return;

    const movedX = Math.abs(event.screenX - state.startScreenX);
    const movedY = Math.abs(event.screenY - state.startScreenY);
    if (movedX > 2 || movedY > 2) {
      state.moved = true;
    }

    window.guardian.move(event.screenX, event.screenY, state.offsetX, state.offsetY);
  };

  const endDrag = (event) => {
    const state = dragRef.current;
    if (!state.active) return;

    dragRef.current = {
      active: false,
      moved: false,
      offsetX: 0,
      offsetY: 0,
      startScreenX: 0,
      startScreenY: 0,
      pointerId: null,
    };

    setDragging(false);
    if (state.moved) suppressClickRef.current = true;

    if (event.currentTarget.hasPointerCapture(state.pointerId)) {
      event.currentTarget.releasePointerCapture(state.pointerId);
    }
  };

  const handleClick = () => {
    if (suppressClickRef.current) {
      suppressClickRef.current = false;
      return;
    }

    if (!expanded) {
      clearDetections();
      expand();
    } else {
      collapse();
    }
  };

  return (
    <motion.button
      onClick={handleClick}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      whileHover={{ scale: 1.12 }}
      whileTap={{ scale: 0.88 }}
      transition={{ type: 'spring', stiffness: 400, damping: 20 }}
      title={latestDetectedIp ? `Nouvelle IP détectée : ${latestDetectedIp}` : undefined}
      style={{
        position: 'relative',
        width: 52,
        height: 52,
        borderRadius: '50%',
        border: 'none',
        cursor: expanded ? 'pointer' : (dragging ? 'grabbing' : 'grab'),
        background: expanded
          ? 'linear-gradient(135deg, #48484a, #636366)'
          : 'linear-gradient(135deg, #ff3b30, #ff6b35)',
        boxShadow: expanded
          ? '0 4px 16px rgba(0,0,0,0.5)'
          : '0 4px 24px rgba(255,59,48,0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 22,
        transition: 'background 0.25s, box-shadow 0.25s',
      }}
    >
      {expanded ? '\u2715' : '\uD83D\uDEE1\uFE0F'}
      {!expanded && newDetectionCount > 0 && (
        <span
          style={{
            position: 'absolute',
            top: -4,
            right: -4,
            minWidth: 18,
            height: 18,
            background: '#ff9500',
            color: '#fff',
            fontSize: 10,
            fontWeight: 700,
            borderRadius: 9,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '0 4px',
            boxShadow: '0 0 6px rgba(255,149,0,0.8)',
            animation: 'pulse 1.5s infinite',
          }}
        >
          {newDetectionCount > 9 ? '9+' : newDetectionCount}
        </span>
      )}
    </motion.button>
  );
}
