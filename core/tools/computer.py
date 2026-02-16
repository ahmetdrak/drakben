# core/computer.py
# DRAKBEN Computer Control Module
# Provides Vision and Input capabilities similar to Open Interpreter
# Powered by PyAutoGUI and OpenCV

import logging
import os

try:
    import pyautogui

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
            msg = "Computer control dependencies (pyautogui, mss, opencv) not installed."
            raise ComputerError(
                msg,
            )

    # ============ MOUSE ============

    def click(
        self,
        x: int | str,
        y: int = 0,
        button: str = "left",
        clicks: int = 1,
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
            # Visual element clicking: try to find element by text on screen
            try:
                import pyautogui

                location = pyautogui.locateOnScreen(x, confidence=0.8)
                if location:
                    center = pyautogui.center(location)
                    pyautogui.click(x=center.x, y=center.y, clicks=clicks, button=button)
                    logger.info("Clicked '%s' at (%s, %s)", x, center.x, center.y)
                    return
            except ImportError:
                pass  # pyautogui not installed
            except (OSError, ValueError, TypeError, RuntimeError) as e:
                logger.warning("Unexpected error during visual element search for '%s': %s", x, e)

            # Fallback: log a helpful warning instead of crashing
            logger.warning(
                "Visual clicking for '%s' could not locate element on screen. Use coordinates instead: click(x, y)",
                x,
            )
            msg = f"Could not locate '{x}' on screen. Use coordinates instead: click(x, y)"
            raise ComputerError(msg)

        # At this point x must be int
        target_x: int = int(x)
        target_y: int = y

        try:
            # Bounds check
            if not self._is_on_screen(target_x, target_y):
                msg = f"Coordinates ({target_x}, {target_y}) are out of bounds ({self.width}x{self.height})"
                raise ComputerError(
                    msg,
                )

            pyautogui.click(x=target_x, y=target_y, clicks=clicks, button=button)
            logger.info("Clicked %s at (%s, %s)", button, target_x, target_y)

        except (ComputerError, OSError, ValueError, TypeError, RuntimeError) as e:
            msg = f"Click failed: {e}"
            raise ComputerError(msg) from e

    def scroll(self, amount: int) -> None:
        """Scroll mouse wheel."""
        self.check_availability()
        try:
            pyautogui.scroll(amount)
        except (OSError, ValueError, TypeError, RuntimeError) as e:
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
        except (OSError, ValueError, TypeError, RuntimeError) as e:
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
        except (OSError, ValueError, TypeError, RuntimeError) as e:
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
