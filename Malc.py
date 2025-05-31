# Python script to create a "malicious" image file

# Path to the original safe image
safe_image_path = 'img1.jpeg'  # Replace with the path to your existing image

# Path for the malicious image to be saved
malicious_image_path = 'malicious_image.jpg'

# Suspicious content to embed in the image
suspicious_content = b'<script>alert("This is a test!");</script>'

# Read the original image data
with open(safe_image_path, 'rb') as safe_image:
    image_data = safe_image.read()

# Create a new file that includes the original image data and the suspicious content
with open(malicious_image_path, 'wb') as malicious_image:
    malicious_image.write(image_data)  # Write the original image data
    malicious_image.write(suspicious_content)  # Append the suspicious content

print(f"Malicious image created: {malicious_image_path}")
