import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import ThreatNetwork from './ThreatNetwork.jsx';
import { Eye, Shield, Globe } from 'lucide-react';

export default function GlobalThreatGlobe3D({ stats }) {
  const mountRef = useRef(null);
  const [webglSupported, setWebglSupported] = useState(true);
  const [viewMode, setViewMode] = useState('3d'); // '3d' or '2d'
  const [hoveredNode, setHoveredNode] = useState(null);

  useEffect(() => {
    if (viewMode !== '3d') return;

    // Check WebGL availability
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) {
        setWebglSupported(false);
        return;
      }
    } catch (e) {
      setWebglSupported(false);
      return;
    }

    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 600;
    const height = 280;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 210;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'low-power' });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Globe Core Wireframe (Dark 3D Sphere)
    const globeRadius = 70;
    const globeGeometry = new THREE.SphereGeometry(globeRadius, 28, 28);
    const globeMaterial = new THREE.MeshBasicMaterial({
      color: 0x00c2ff,
      wireframe: true,
      transparent: true,
      opacity: 0.15,
    });
    const globe = new THREE.Mesh(globeGeometry, globeMaterial);
    scene.add(globe);

    // Inner subtle glow core
    const innerGeometry = new THREE.SphereGeometry(globeRadius - 2, 24, 24);
    const innerMaterial = new THREE.MeshBasicMaterial({
      color: 0x0a1628,
      transparent: true,
      opacity: 0.85,
    });
    const innerSphere = new THREE.Mesh(innerGeometry, innerMaterial);
    scene.add(innerSphere);

    // Latitude rings for SOC aesthetic
    const ringGroup = new THREE.Group();
    [-40, -20, 0, 20, 40].forEach((lat) => {
      const rad = (lat * Math.PI) / 180;
      const r = globeRadius * Math.cos(rad);
      const y = globeRadius * Math.sin(rad);
      const ringGeom = new THREE.RingGeometry(r - 0.5, r, 48);
      const ringMat = new THREE.MeshBasicMaterial({ color: 0x00c2ff, side: THREE.DoubleSide, transparent: true, opacity: 0.12 });
      const ringMesh = new THREE.Mesh(ringGeom, ringMat);
      ringMesh.rotation.x = Math.PI / 2;
      ringMesh.position.y = y;
      ringGroup.add(ringMesh);
    });
    globe.add(ringGroup);

    // Telemetry Threat Nodes (Anonymized coordinates)
    const sampleNodes = [
      { lat: 37.77, lon: -122.41, type: 'CRITICAL', label: 'Suspicious Domain DGA', threat: true },
      { lat: 40.71, lon: -74.00, type: 'HIGH', label: 'Brand Impersonation Link', threat: true },
      { lat: 51.50, lon: -0.12, type: 'SAFE', label: 'Legitimate SSL Endpoint', threat: false },
      { lat: 48.85, lon: 2.35, type: 'MEDIUM', label: 'Homoglyph Hostname', threat: true },
      { lat: 35.68, lon: 139.69, type: 'CRITICAL', label: 'Raw IP Credential Portal', threat: true },
      { lat: -33.86, lon: 151.20, type: 'SAFE', label: 'Clean MX Gateway', threat: false },
      { lat: 1.35, lon: 103.81, type: 'HIGH', label: 'Obfuscated Redirect Script', threat: true },
      { lat: 55.75, lon: 37.61, type: 'SUSPICIOUS', label: 'Punycode Host', threat: true },
      { lat: -23.55, lon: -46.63, type: 'SAFE', label: 'Verified Cloud CDN', threat: false },
      { lat: 28.61, lon: 77.20, type: 'MEDIUM', label: 'Elevated Shannon Entropy', threat: true },
    ];

    const nodesGroup = new THREE.Group();
    const nodeMeshes = [];

    sampleNodes.forEach((node, idx) => {
      const phi = (90 - node.lat) * (Math.PI / 180);
      const theta = (node.lon + 180) * (Math.PI / 180);
      const x = -(globeRadius * Math.sin(phi) * Math.cos(theta));
      const z = globeRadius * Math.sin(phi) * Math.sin(theta);
      const y = globeRadius * Math.cos(phi);

      const color = node.threat ? (node.type === 'CRITICAL' ? 0xef4444 : 0xf59e0b) : 0x10b981;
      const dotGeom = new THREE.SphereGeometry(2.2, 12, 12);
      const dotMat = new THREE.MeshBasicMaterial({ color });
      const dotMesh = new THREE.Mesh(dotGeom, dotMat);
      dotMesh.position.set(x, y, z);
      dotMesh.userData = node;

      // Outer pulse ring
      if (node.threat) {
        const pulseGeom = new THREE.RingGeometry(2.6, 3.8, 16);
        const pulseMat = new THREE.MeshBasicMaterial({ color, side: THREE.DoubleSide, transparent: true, opacity: 0.6 });
        const pulseMesh = new THREE.Mesh(pulseGeom, pulseMat);
        pulseMesh.lookAt(new THREE.Vector3(x * 2, y * 2, z * 2));
        pulseMesh.position.set(x * 1.01, y * 1.01, z * 1.01);
        dotMesh.add(pulseMesh);
      }

      nodesGroup.add(dotMesh);
      nodeMeshes.push(dotMesh);
    });

    globe.add(nodesGroup);

    // Arcs connecting threat nodes
    const curvePoints = [];
    for (let i = 0; i < nodeMeshes.length - 1; i += 2) {
      const v1 = nodeMeshes[i].position.clone();
      const v2 = nodeMeshes[i + 1].position.clone();
      const mid = v1.clone().add(v2).multiplyScalar(0.5);
      mid.normalize().multiplyScalar(globeRadius + 18);
      const curve = new THREE.QuadraticBezierCurve3(v1, mid, v2);
      const pts = curve.getPoints(24);
      const geom = new THREE.BufferGeometry().setFromPoints(pts);
      const mat = new THREE.LineBasicMaterial({
        color: nodeMeshes[i].userData.threat ? 0xef4444 : 0x00c2ff,
        transparent: true,
        opacity: 0.35,
      });
      const line = new THREE.Line(geom, mat);
      globe.add(line);
    }

    // Mouse Interaction (Rotation on Drag, Hover Raycast)
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;
    let rotationVelocityX = 0.003;
    let rotationVelocityY = 0;

    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const onMouseDown = (e) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const onMouseMove = (e) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      if (isDragging) {
        const deltaX = e.clientX - prevMouseX;
        const deltaY = e.clientY - prevMouseY;
        globe.rotation.y += deltaX * 0.008;
        globe.rotation.x += deltaY * 0.008;
        prevMouseX = e.clientX;
        prevMouseY = e.clientY;
      } else {
        raycaster.setFromCamera(mouse, camera);
        const intersects = raycaster.intersectObjects(nodeMeshes, true);
        if (intersects.length > 0) {
          const target = intersects[0].object.userData.label ? intersects[0].object : intersects[0].object.parent;
          if (target && target.userData) {
            setHoveredNode(target.userData);
          }
        } else {
          setHoveredNode(null);
        }
      }
    };

    const onMouseUp = () => { isDragging = false; };

    container.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // Animation Loop
    let animId;
    const animate = () => {
      animId = requestAnimationFrame(animate);
      if (!isDragging) {
        globe.rotation.y += rotationVelocityX;
      }
      renderer.render(scene, camera);
    };
    animate();

    // Resize Observer
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) {
          camera.aspect = w / height;
          camera.updateProjectionMatrix();
          renderer.setSize(w, height);
        }
      }
    });
    ro.observe(container);

    // Cleanup
    return () => {
      cancelAnimationFrame(animId);
      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      ro.disconnect();
      if (renderer.domElement && renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
      globeGeometry.dispose();
      globeMaterial.dispose();
    };
  }, [viewMode]);

  if (!webglSupported || viewMode === '2d') {
    return (
      <div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 6 }}>
          <button
            className="btn-ghost"
            onClick={() => setViewMode('3d')}
            style={{ fontSize: 11, padding: '3px 8px', display: 'flex', alignItems: 'center', gap: 4 }}
          >
            <Globe size={12} /> Switch to 3D Globe
          </button>
        </div>
        <ThreatNetwork stats={stats} />
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: 280, borderRadius: 12, overflow: 'hidden' }}>
      {/* 3D Canvas Mount Point */}
      <div ref={mountRef} style={{ width: '100%', height: '100%', cursor: 'grab' }} />

      {/* Header telemetry overlay */}
      <div style={{ position: 'absolute', top: 12, left: 14, pointerEvents: 'none' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00c2ff', boxShadow: '0 0 8px #00c2ff' }} />
          <span style={{ fontSize: 11, fontWeight: 700, color: '#00c2ff', letterSpacing: '0.06em' }}>GLOBAL THREAT TELEMETRY (3D)</span>
        </div>
        <span style={{ fontSize: 10, color: '#64748b' }}>Drag to rotate • Anonymized activity stream</span>
      </div>

      {/* Mode toggle */}
      <div style={{ position: 'absolute', top: 10, right: 14, zIndex: 10 }}>
        <button
          className="btn-ghost"
          onClick={() => setViewMode('2d')}
          style={{ fontSize: 11, padding: '4px 8px', background: 'rgba(2,6,23,0.8)' }}
        >
          2D Topology
        </button>
      </div>

      {/* Hover Card */}
      {hoveredNode && (
        <div className="glass-card fade-in" style={{
          position: 'absolute', bottom: 36, left: 14, padding: '8px 12px',
          borderRadius: 8, border: '1px solid rgba(0,194,255,0.3)', pointerEvents: 'none',
        }}>
          <div style={{ fontSize: 10, color: hoveredNode.threat ? '#ef4444' : '#10b981', fontWeight: 700 }}>
            {hoveredNode.type} SIGNAL
          </div>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#f1f5f9' }}>{hoveredNode.label}</div>
        </div>
      )}

      {/* Mandatory honesty label */}
      <div style={{ position: 'absolute', bottom: 8, right: 14, pointerEvents: 'none' }}>
        <span style={{ fontSize: 9, color: '#475569', letterSpacing: '0.05em', textTransform: 'uppercase' }}>
          Threat Activity Visualization — Anonymized Stream
        </span>
      </div>
    </div>
  );
}
