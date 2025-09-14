import time

def print_progress(message, delay=0.2):
    print(f"🔄 {message}")
    time.sleep(delay)

def print_success(message):
    print(f"✅ {message}")

def print_warning(message):
    print(f"⚠️  {message}")

def print_error(message):
    print(f"❌ {message}")

def print_critical(message):
    print(f"🚨 {message}")