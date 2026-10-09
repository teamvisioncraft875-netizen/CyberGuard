import React from 'react';
import { Badge } from './Badge';

export function RiskBadge({ level, style }) {
  return <Badge level={level} text={level} style={style} />;
}

export default RiskBadge;
