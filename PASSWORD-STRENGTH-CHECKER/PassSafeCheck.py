import re

def colorize(text, color):
    colors = {
        "red": "\033[91m",
        "yellow": "\033[93m",
        "green": "\033[92m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "reset": "\033[0m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) < 8:
        feedback.append(colorize("Password is too short (minimum 8 characters required).", "red"))
    elif len(password) >= 12:
        score += 2
    else:
        score += 1

    if not re.search(r'[A-Z]', password):
        feedback.append(colorize("Add at least one uppercase letter for better strength.", "yellow"))
    else:
        score += 1

    if not re.search(r'[a-z]', password):
        feedback.append(colorize("Add at least one lowercase letter for better strength.", "yellow"))
    else:
        score += 1

    if not re.search(r'[0-9]', password):
        feedback.append(colorize("Add at least one digit for better strength.", "yellow"))
    else:
        score += 1

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        feedback.append(colorize("Add at least one special character (e.g., !@#$%^&*) for better strength.", "yellow"))
    else:
        score += 1

    if len(set(password)) <= len(password) // 2:
        feedback.append(colorize("Avoid using repetitive or predictable patterns.", "yellow"))
    else:
        score += 1

    if score <= 2:
        strength = colorize("Weak", "red")
    elif score <= 4:
        strength = colorize("Moderate", "yellow")
    else:
        strength = colorize("Strong", "green")

    feedback.insert(0, f"Password strength: {strength}")
    return "\n".join(feedback)

if __name__ == "__main__":
    print(colorize("Password Strength Checker", "cyan"))
    user_password = input(colorize("Enter your password: ", "cyan"))
    print(check_password_strength(user_password))
