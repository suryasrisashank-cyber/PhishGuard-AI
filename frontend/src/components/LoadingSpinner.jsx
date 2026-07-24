import React from 'react';

export default function LoadingSpinner({ size=36 }){
  return (
    <div style={{width:size,height:size,display:'flex',alignItems:'center',justifyContent:'center'}}>
      <svg width={size} height={size} viewBox="0 0 50 50">
        <circle cx="25" cy="25" r="20" stroke="#0b1220" strokeWidth="6" fill="none" />
        <path d="M45 25a20 20 0 0 1-20 20" stroke="#00c2ff" strokeWidth="6" strokeLinecap="round" fill="none">
          <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
        </path>
      </svg>
    </div>
  )
}
