'use client';
import React from 'react';
import FindingDetailModal from './FindingDetailModal';
import { Finding } from '../lib/types';

interface FindingsDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onAskAi?: (finding: Finding) => void;
}

export default function FindingsDrawer({ finding, onClose, onAskAi }: FindingsDrawerProps) {
  return (
    <FindingDetailModal
      finding={finding}
      onClose={onClose}
      onAskAi={onAskAi}
    />
  );
}
