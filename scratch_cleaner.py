import os
import re
try:
    import emoji
except ImportError:
    import subprocess
    subprocess.run(["pip", "install", "emoji"])
    import emoji

def remove_emojis(text):
    return emoji.replace_emoji(text, replace='')

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    new_content = remove_emojis(content)
    
    # Also look for common icons like , , , , , , , , , , , 
    # emoji package should catch them, but just in case
    extra_icons = ['', '', '', '', '', '', '', '', '', '', '', '', '', '']
    for icon in extra_icons:
        new_content = new_content.replace(icon, '')
        
    if content != new_content:
        print(f"Removed emojis from {filepath}")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

for root, dirs, files in os.walk('.'):
    if '.venv' in root or '.git' in root or '__pycache__' in root:
        continue
    for file in files:
        if file.endswith('.py'):
            process_file(os.path.join(root, file))

print("Emoji cleanup done.")
