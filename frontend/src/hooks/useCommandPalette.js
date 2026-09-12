/**
 * PhishGuard AI 2.0 — Global Ctrl+K command palette hook
 */
import { useEffect, useCallback } from 'react';

export function useCommandPalette(onOpen) {
  const handleKeyDown = useCallback((e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      onOpen();
    }
  }, [onOpen]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);
}

export default useCommandPalette;
