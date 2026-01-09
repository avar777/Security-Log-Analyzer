/**
 * Attack Map Card
 * Overlays attack hotspots on a world map image with a tooltip
 * 
 * Author: Ava Raper
 */

import React, { useState } from 'react';
import { MapPin } from 'lucide-react';

const AttackMap = ({ attackData }) => {
  const [hoveredLocation, setHoveredLocation] = useState(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  // Don't show if no data
  if (!attackData || attackData.length === 0) {
    return null;
  }

  const width = 1000;
  const height = 500;

  // Convert lat/lng to SVG coordinates (equirectangular projection)
  const projectCoordinates = (lat, lng) => {
    const x = ((lng + 180) * width) / 360;
    const y = ((90 - lat) * height) / 180;
    return { x, y };
  };

  // Track mouse position
  const handleMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    });
  };

  // Find max attacks for scaling
  const maxAttacks = Math.max(...attackData.map(d => d.attacks));

  // Get circle radius and opacity based on attack count
  const getCircleProps = (attacks) => {
    const minRadius = 8;
    const maxRadius = 25;
    const radius = minRadius + (attacks / maxAttacks) * (maxRadius - minRadius);
    const opacity = 0.6 + (attacks / maxAttacks) * 0.3;
    return { radius, opacity };
  };

  const mapImageUrl = "https://upload.wikimedia.org/wikipedia/commons/b/b9/World2012.PNG";

  return (
    <div className="attack-map-container">
      <div className="attack-map-header">
        <MapPin size={18} />
        <h3>Attack Origins</h3>
      </div>

      <div className="world-map-wrapper" onMouseMove={handleMouseMove}>
        <div className="world-map-image-container">
          <svg 
            viewBox={`0 0 ${width} ${height}`} 
            className="world-map-svg"
          >
            {/* World map as background image */}
            <image 
              href={mapImageUrl}
              width={width} 
              height={height}
              preserveAspectRatio="xMidYMid slice"
              opacity="0.9"
            />

            {/* Attack hotspots overlaid */}
            {attackData.map((location, idx) => {
              const { x, y } = projectCoordinates(location.lat, location.lng);
              const { radius, opacity } = getCircleProps(location.attacks);
              
              return (
                <g 
                  key={idx}
                  onMouseEnter={() => setHoveredLocation(location)}
                  onMouseLeave={() => setHoveredLocation(null)}
                  style={{ cursor: 'pointer' }}
                >
                  {/* Outer glow */}
                  <circle
                    cx={x}
                    cy={y}
                    r={radius + 8}
                    fill="#d98572"
                    opacity="0.15"
                  />
                  {/* Main hotspot */}
                  <circle
                    cx={x}
                    cy={y}
                    r={radius}
                    fill="#d98572"
                    opacity={opacity}
                    className="attack-hotspot"
                  />
                </g>
              );
            })}
          </svg>

          {/* Cursor-following tooltip */}
          {hoveredLocation && (
            <div 
              className="map-tooltip"
              style={{
                left: `${mousePos.x + 15}px`,
                top: `${mousePos.y + 15}px`
              }}
            >
              <strong>{hoveredLocation.country}</strong>
              <div>{hoveredLocation.attacks} Threat{hoveredLocation.attacks !== 1 ? 's' : ''}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AttackMap;

