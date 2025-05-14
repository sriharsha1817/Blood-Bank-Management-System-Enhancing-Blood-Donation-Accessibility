from werkzeug.security import generate_password_hash

# Replace 'your_password_here' with the actual password
new_password = "admin"
hashed_password = generate_password_hash(new_password)
print(hashed_password)  # For reference