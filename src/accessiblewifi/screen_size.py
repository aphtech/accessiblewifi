import gi
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk


class ScreenSize:
    """Class to get screen dimensions with fallback handling."""
    
    def __init__(self):
        """Initialize and detect screen dimensions."""
        self.width = 1920  # default fallback
        self.height = 1080  # default fallback
        self._detect_screen()
    
    def _detect_screen(self):
        """Detect screen dimensions from the display."""
        display = Gdk.Display.get_default()
        
        if display is None:
            print("ERROR: No display found! Using fallback dimensions.")
            return
        
        #print(f"Display found: {display.get_name()}")
        #print(f"Number of monitors: {display.get_n_monitors()}")
        
        # Try primary monitor first
        monitor = display.get_primary_monitor()
        
        if monitor is not None:
            #print("Primary monitor found")
            geometry = monitor.get_geometry()
            self.width = geometry.width
            self.height = geometry.height
            #print(f"Primary monitor width: {self.width}")
            #print(f"Primary monitor height: {self.height}")
        elif display.get_n_monitors() > 0:
            #print("No primary monitor, using first monitor")
            monitor = display.get_monitor(0)
            geometry = monitor.get_geometry()
            self.width = geometry.width
            self.height = geometry.height
            #print(f"First monitor width: {self.width}")
            #print(f"First monitor height: {self.height}")
        else:
            print("ERROR: No monitors detected! Using fallback dimensions.")
    
    def get_width(self):
        """Return the screen width."""
        return self.width
    
    def get_height(self):
        """Return the screen height."""
        return self.height
    
    def get_dimensions(self):
        """Return both width and height as a tuple."""
        return (self.width, self.height)


# Example usage:
if __name__ == "__main__":
    screen = ScreenSize()
    #print(f"\nFinal dimensions: {screen.get_width()} x {screen.get_height()}")
    #print(f"As tuple: {screen.get_dimensions()}")