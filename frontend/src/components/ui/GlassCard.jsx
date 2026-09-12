import React from 'react';

export default function GlassCard({ children, className = '', hover = false, style = {}, ...props }) {
  return (
    <div
      className={`glass-card ${hover ? 'glass-card-hover' : ''} ${className}`}
      style={{ borderRadius: 14, ...style }}
      {...props}
    >
      {children}
    </div>
  );
}
