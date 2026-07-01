import os
import json
import hashlib
import getpass

CONFIG_FILE = "htd_config.json"

def clear_terminal():
    """Clears the terminal screen completely across different operating systems."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_initial_config():
    return {
        "cv_enabled": False,
        "cv_hash": None
    }

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return get_initial_config()
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return get_initial_config()

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode('utf-8')).hexdigest()

def verify_current_code(config) -> bool:
    """Forces authorization using hidden input before allowing administrative changes."""
    if not config["cv_hash"]:
        return True
        
    # getpass hides the keys entirely as they are typed
    entered_pin = getpass.getpass("Enter current CV Code to make changes (typing will be hidden): ").strip()
    if hash_pin(entered_pin) == config["cv_hash"]:
        return True
    else:
        clear_terminal()
        print("CV code could not be de-hashed ")
        input("\nPress Enter to return to menu...")
        return False

def run_setup_menu():
    while True:
        clear_terminal() # Keep the main entry point clean
        config = load_config()
        status = "ENABLED" if config["cv_enabled"] else "DISABLED"
        
        print("======================================")
        print(f"      CV code setup | HTD     ")
        print("======================================")
        print(f"Code condition: [{status}]")
        print("--------------------------------------")
        print("1. Set / Change CV Code")
        print("2. Toggle CV Code requierement On/Off")
        print("3. Exit to Desktop")
        print("--------------------------------------")
        
        choice = input("Select an option (1-3): ").strip()
        clear_terminal() # Clear instantly after menu choice selection
        
        if choice == "1":
            if not verify_current_code(config):
                continue
                
            clear_terminal()
            new_pin = getpass.getpass("Enter new numeric CV Code (typing will be hidden): ").strip()
            if not new_pin.isdigit():
                clear_terminal()
                print("Please make sure your CV code is purley numeric")
                input("\nPress Enter to return to menu...")
                continue
            
            config["cv_hash"] = hash_pin(new_pin)
            config["cv_enabled"] = True
            save_config(config)
            clear_terminal()
            print("CV Code registered! You are good to go")
            input("\nPress Enter to return to menu...")
            
        elif choice == "2":
            if not config["cv_hash"]:
                print("No CV Code setup. Please set a code first using Option 1.")
                input("\nPress Enter to return to menu...")
                continue
            
            if not verify_current_code(config):
                continue
            
            config["cv_enabled"] = not config["cv_enabled"]
            save_config(config)
            new_status = "ENABLED" if config["cv_enabled"] else "DISABLED"
            clear_terminal()
            print(f"New Condition: {new_status}")
            input("\nPress Enter to return to menu...")
            
        elif choice == "3":
            clear_terminal()
            print("Exit setup?")
            break
        else:
            print("Invalid String")
            input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    run_setup_menu()