import { useState, useCallback } from 'react';

/**
 * Convenient state manager for Modals and Drawers
 */
export function useModal(initialOpen = false) {
  const [isOpen, setIsOpen] = useState(initialOpen);
  const [modalData, setModalData] = useState(null);

  const open = useCallback((data = null) => {
    setModalData(data);
    setIsOpen(true);
  }, []);

  const close = useCallback(() => {
    setIsOpen(false);
    setModalData(null);
  }, []);

  const toggle = useCallback(() => {
    setIsOpen((prev) => !prev);
  }, []);

  return {
    isOpen,
    data: modalData,
    open,
    close,
    toggle,
  };
}
