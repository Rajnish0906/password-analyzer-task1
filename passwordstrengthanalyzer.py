import re
import secrets
import string

def check_password_strength(password):
    """
    Evaluates password strength based on length, complexity, 
    and checks for sequential or repeating characters.
    """
    score = 0
    feedback = []

    # 1. Length Evaluation
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("• Password is too short (aim for at least 12 characters).")

    # 2. Complexity Evaluations (Character Types)
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("• Add uppercase letters (A-Z).")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("• Add lowercase letters (a-z).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("• Add numbers (0-9).")

    if re.search(r"[ !@#$%^&*(),.?\":{}|<>_+\-\[\]\/\\]", password):
        score += 1
    else:
        feedback.append("• Add special characters (e.g., @, #, $, %).")

    # 3. Pattern / Uniqueness Evaluation
    # Check for 3+ identical repeating characters (e.g., "aaa")
    if re.search(r"(.)\1\1", password):
        score -= 1
        feedback.append("• Avoid repeating the same character 3+ times consecutively.")
        
    # Check for basic sequential patterns
    if "123" in password or "abc" in password.lower():
        score -= 1
        feedback.append("• Avoid common sequential patterns (like '123' or 'abc').")

    # Map score to rating
    if score >= 5:
        rating = "STRONG"
    elif 3 <= score < 5:
        rating = "MEDIUM"
    else:
        rating = "WEAK"

    return rating, feedback

def generate_strong_alternative(length=16):
    """
    Generates a cryptographically secure, strong password alternative.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+"
    
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure it meets strong criteria immediately
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*()_+" for c in password)):
            return password

def main():
    print("=" * 45)
    print("      🔐 PASSWORD STRENGTH ANALYZER 🔐      ")
    print("=" * 45)
    
    user_password = input("Enter a password to evaluate: ").strip()
    
    if not user_password:
        print("\n❌ Error: Password cannot be empty.")
        return

    rating, feedback = check_password_strength(user_password)
    
    print("\n--- Results ---")
    if rating == "STRONG":
        print(f"Overall Strength: ✅ {rating}")
        print("Great job! Your password meets strict security standards.")
    elif rating == "MEDIUM":
        print(f"Overall Strength: ⚠️ {rating}")
    else:
        print(f"Overall Strength: ❌ {rating}")

    if feedback:
        print("\nSuggestions to improve:")
        for tip in feedback:
            print(tip)

    print("\n" + "-" * 45)
    print("💡 Need a better alternative?")
    print(f"Suggested Strong Password: {generate_strong_alternative()}")
    print("=" * 45)

if __name__ == "__main__":
    main()