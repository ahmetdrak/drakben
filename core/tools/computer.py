# core/computer.py
# DRAKBEN Computer Control Module
# Provides Vision and Input capabilities similar to Open Interpreter
# Powered by PyAutoGUI and OpenCV

import logging
import os
import time

try:
    import mss
    import pyautogui
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
    """Custom exception for computer control errors."""


class Computer:
    """Computer Controller - "The Eyes and Hands of Drakben".

    Capabilities:
    1. Vision: See the screen (screenshot, find text/images)
    2. Control: Mouse and Keyboard interaction
    """

    def __init__(self, screenshot_dir: str = "logs/screenshots") -> None:
        self.screenshot_dir = screenshot_dir
        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)

        self.width, self.height = (0, 0)
        if COMPUTER_AVAILABLE:
            self.width, self.height = pyautogui.size()

    def check_availability(self) -> None:
        """Check if dependencies are available."""
        if not COMPUTER_AVAILABLE:
            msg = (
                "Computer control dependencies (pyautogui, mss, opencv) not installed."
            )
            raise ComputerError(
                msg,
            )

    # ============ VISION ============

    def screenshot(self, filename: str | None = None) -> str:
        """Take a screenshot and save it.

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

            logger.info("Screenshot saved to %s", absolute_path)
            return absolute_path
        except Exception as e:
            logger.exception("Screenshot failed: %s", e)
            msg = f"Screenshot failed: {e}"
            raise ComputerError(msg) from e

    # ============ MOUSE ============

    def click(
        self, x: int | str, y: int = 0, button: str = "left", clicks: int = 1,
    ) -> None:
        """Click at coordinates or on an image/text match.

        Args:
            x: X coordinate OR text/image-path to find and click
            y: Y coordinate (if x is int)
            button: 'left', 'right', 'middle'
            clicks: Number of clicks

        """
        self.check_availability()

        if isinstance(x, str):
            # For now, just log and fail safe
            msg = "Visual clicking (click('Submit')) not yet implemented. Use coordinates."
            raise NotImplementedError(
                msg,
            )

        # At this point x must be int
        target_x: int = int(x)
        target_y: int = y

        try:
            # Bounds check
            if not self._is_on_screen(target_x, target_y):
                msg = (
                    f"Coordinates ({target_x}, {target_y}) are out of bounds "
                    f"({self.width}x{self.height})"
                )
                raise ComputerError(
                    msg,
                )

            pyautogui.click(x=target_x, y=target_y, clicks=clicks, button=button)
            logger.info("Clicked %s at (%s, %s)", button, target_x, target_y)

        except Exception as e:
            msg = f"Click failed: {e}"
            raise ComputerError(msg) from e

    def move(self, x: int, y: int) -> None:
        """Move mouse to coordinates."""
        self.check_availability()
        try:
            pyautogui.moveTo(x, y)
        except Exception as e:
            msg = f"Move failed: {e}"
            raise ComputerError(msg) from e

    def scroll(self, amount: int) -> None:
        """Scroll mouse wheel."""
        self.check_availability()
        try:
            pyautogui.scroll(amount)
        except Exception as e:
            msg = f"Scroll failed: {e}"
            raise ComputerError(msg) from e

    # ============ KEYBOARD ============

    def type(self, text: str, interval: float = 0.05) -> None:
        """Type text.

        Args:
            text: Text to type
            interval: Delay between key presses

        """
        self.check_availability()
        try:
            pyautogui.write(text, interval=interval)
            logger.info("Typed text (length %s)", len(text))
        except Exception as e:
            msg = f"Type failed: {e}"
            raise ComputerError(msg) from e

    def press(self, keys: str | list[str]) -> None:
        """Press a key or combination.

        Args:
            keys: Single key 'enter' or list ['ctrl', 'c']

        """
        self.check_availability()
        try:
            if isinstance(keys, str):
                pyautogui.press(keys)
            # For combinations like hotkeys
            elif len(keys) > 1:
                pyautogui.hotkey(*keys)
            else:
                pyautogui.press(keys[0])
            logger.info("Pressed %s", keys)
        except Exception as e:
            msg = f"Press failed: {e}"
            raise ComputerError(msg) from e

    # ============ UTILS ============

    def _is_on_screen(self, x: int, y: int) -> bool:
        """Check if coordinates are valid."""
        return 0 <= x < self.width and 0 <= y < self.height

    def position(self) -> tuple[int, int]:
        """Get current mouse position."""
        self.check_availability()
        return pyautogui.position()

    def size(self) -> tuple[int, int]:
        """Get screen size."""
        self.check_availability()
        return pyautogui.size()


# Global instance
computer = Computer()
