# core/computer.py
# DRAKBEN Computer Control Module
# Provides Vision and Input capabilities similar to Open Interpreter
# Powered by PyAutoGUI and OpenCV

import logging
import os
import platform
import time
from typing import Dict, List, Optional, Tuple, Union

try:
    import pyautogui
    import mss
    import cv2
    import numpy as np
    from PIL import Image
    COMPUTER_AVAILABLE = True
except ImportError:
    COMPUTER_AVAILABLE = False

# Setup logging
logger = logging.getLogger(__name__)

# Safety settings
if COMPUTER_AVAILABLE:
    pyautogui.FAILSAFE = True
    pyautogui.PAUSE = 0.5  # Add delay between actions

class ComputerError(Exception):
    """Custom exception for computer control errors"""
    pass

class Computer:
    """
    Computer Controller - "The Eyes and Hands of Drakben"
    
    Capabilities:
    1. Vision: See the screen (screenshot, find text/images)
    2. Control: Mouse and Keyboard interaction
    """
    
    def __init__(self, screenshot_dir: str = "logs/screenshots"):
        self.screenshot_dir = screenshot_dir
        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)
            
        self.width, self.height = (0, 0)
        if COMPUTER_AVAILABLE:
            self.width, self.height = pyautogui.size()
            
    def check_availability(self):
        """Check if dependencies are available"""
        if not COMPUTER_AVAILABLE:
            raise ComputerError("Computer control dependencies (pyautogui, mss, opencv) not installed.")

    # ============ VISION ============
    
    def screenshot(self, filename: Optional[str] = None) -> str:
        """
        Take a screenshot and save it.
        
        Args:
            filename: Optional filename. If None, auto-generated timestamp.
            
        Returns:
            Absolute path to the saved screenshot.
        """
        self.check_availability()
        
        if not filename:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"screenshot_{timestamp}.png"
            
        filepath = os.path.join(self.screenshot_dir, filename)
        absolute_path = os.path.abspath(filepath)
        
        try:
            with mss.mss() as sct:
                # Capture the first monitor
                monitor = sct.monitors[1]
                sct_img = sct.grab(monitor)
                
                # Convert to PIL/PNG
                img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                img.save(absolute_path)
                
            logger.info(f"Screenshot saved to {absolute_path}")
            return absolute_path
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            raise ComputerError(f"Screenshot failed: {e}")

    # ============ MOUSE ============
    
    def click(self, x: Union[int, str], y: int = 0, button: str = "left", clicks: int = 1):
        """
        Click at coordinates or on an image/text match.
        
        Args:
            x: X coordinate OR text/image-path to find and click
            y: Y coordinate (if x is int)
            button: 'left', 'right', 'middle'
            clicks: Number of clicks
        """
        self.check_availability()
        
        target_x, target_y = x, y
        
        # If x is a string, treat it as a visual target (advanced)
        if isinstance(x, str):
            # TODO: Implement "click on text" via OCR or "click on image" via template matching
            # For now, just log and fail safe
            raise NotImplementedError("Visual clicking (click('Submit')) not yet implemented. Use coordinates.")
            
        try:
            # Bounds check
            if not self._is_on_screen(target_x, target_y):
                raise ComputerError(f"Coordinates ({target_x}, {target_y}) are out of bounds ({self.width}x{self.height})")
                
            pyautogui.click(x=target_x, y=target_y, clicks=clicks, button=button)
            logger.info(f"Clicked {button} at ({target_x}, {target_y})")
            
        except Exception as e:
            raise ComputerError(f"Click failed: {e}")

    def move(self, x: int, y: int):
        """Move mouse to coordinates"""
        self.check_availability()
        try:
            pyautogui.moveTo(x, y)
        except Exception as e:
            raise ComputerError(f"Move failed: {e}")
            
    def scroll(self, amount: int):
        """Scroll mouse wheel"""
        self.check_availability()
        try:
            pyautogui.scroll(amount)
        except Exception as e:
            raise ComputerError(f"Scroll failed: {e}")

    # ============ KEYBOARD ============

    def type(self, text: str, interval: float = 0.05):
        """
        Type text.
        
        Args:
            text: Text to type
            interval: Delay between key presses
        """
        self.check_availability()
        try:
            pyautogui.write(text, interval=interval)
            logger.info(f"Typed text (length {len(text)})")
        except Exception as e:
            raise ComputerError(f"Type failed: {e}")
            
    def press(self, keys: Union[str, List[str]]):
        """
        Press a key or combination.
        
        Args:
            keys: Single key 'enter' or list ['ctrl', 'c']
        """
        self.check_availability()
        try:
            if isinstance(keys, str):
                pyautogui.press(keys)
            else:
                # For combinations like hotkeys
                if len(keys) > 1:
                    pyautogui.hotkey(*keys)
                else:
                    pyautogui.press(keys[0])
            logger.info(f"Pressed {keys}")
        except Exception as e:
            raise ComputerError(f"Press failed: {e}")

    # ============ UTILS ============

    def _is_on_screen(self, x: int, y: int) -> bool:
        """Check if coordinates are valid"""
        return 0 <= x < self.width and 0 <= y < self.height

    def position(self) -> Tuple[int, int]:
        """Get current mouse position"""
        self.check_availability()
        return pyautogui.position()
        
    def size(self) -> Tuple[int, int]:
        """Get screen size"""
        self.check_availability()
        return pyautogui.size()

# Global instance
computer = Computer()
