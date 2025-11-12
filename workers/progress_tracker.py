# workers/progress_tracker.py
import sys
from datetime import datetime, timedelta
from typing import Optional


class ProgressTracker:
    """Track and display scan progress."""

    def __init__(self, total: int = 0, show_bar: bool = True):
        """
        Initialize progress tracker.

        Args:
            total: Total number of items
            show_bar: Display progress bar in terminal
        """
        self.total = total
        self.completed = 0
        self.show_bar = show_bar
        self.start_time = datetime.now()
        self.last_update = self.start_time

    def update(self, completed: int, total: Optional[int] = None, current_item: str = ""):
        """
        Update progress.

        Args:
            completed: Number of completed items
            total: Total items (updates self.total if provided)
            current_item: Description of current item
        """
        self.completed = completed
        if total is not None:
            self.total = total

        if self.show_bar:
            self._display_progress(current_item)

    def _display_progress(self, current_item: str = ""):
        """Display progress bar in terminal."""
        if self.total == 0:
            return

        percentage = (self.completed / self.total) * 100
        bar_length = 50
        filled_length = int(bar_length * self.completed / self.total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)

        # Calculate ETA
        elapsed = datetime.now() - self.start_time
        if self.completed > 0:
            avg_time_per_item = elapsed.total_seconds() / self.completed
            remaining_items = self.total - self.completed
            eta_seconds = avg_time_per_item * remaining_items
            eta = timedelta(seconds=int(eta_seconds))
        else:
            eta = timedelta(0)

        # Truncate current_item if too long
        max_item_length = 40
        if len(current_item) > max_item_length:
            current_item = "..." + current_item[-(max_item_length - 3):]

        # Display
        sys.stdout.write(f'\r')
        sys.stdout.write(
            f'|{bar}| {self.completed}/{self.total} '
            f'({percentage:.1f}%) '
            f'ETA: {eta} '
            f'[{current_item}]'
        )
        sys.stdout.write(' ' * 10)  # Clear any trailing chars
        sys.stdout.flush()

        # New line when complete
        if self.completed >= self.total:
            sys.stdout.write('\n')
            elapsed_str = str(timedelta(seconds=int(elapsed.total_seconds())))
            print(f"Completed in {elapsed_str}")

    def finish(self):
        """Mark progress as finished."""
        if self.show_bar and self.completed < self.total:
            self.update(self.total, self.total, "Done")
