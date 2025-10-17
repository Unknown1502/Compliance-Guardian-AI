"""
Script to remove all emojis from markdown files
"""
import re
from pathlib import Path

# Common emojis to remove
EMOJI_PATTERNS = [
    r'[\U0001F300-\U0001F9FF]',  # Emoticons
    r'[\U0001F600-\U0001F64F]',  # Emoticons
    r'[\U0001F680-\U0001F6FF]',  # Transport & Map
    r'[\U0001F1E0-\U0001F1FF]',  # Flags
    r'[\U00002600-\U000027BF]',  # Misc symbols
    r'[\U0001F900-\U0001F9FF]',  # Supplemental Symbols
    r'[\U00002700-\U000027BF]',  # Dingbats
]

# Specific emoji mappings for contextual replacement
EMOJI_REPLACEMENTS = {
    '✅': '[✓]',
    '❌': '[✗]',
    '⚠️': '[!]',
    '🔍': '',
    '🤖': '',
    '⚡': '',
    '🔄': '',
    '📊': '',
    '🌐': '',
    '📁': '',
    '📖': '',
    '🎬': '',
    '💻': '',
    '📋': '',
    '💡': '',
    '🚀': '',
    '🔗': '',
    '📱': '',
    '🤝': '',
    '⚖️': '',
    '🎨': '',
    '🛠️': '',
    '📸': '',
    '🎯': '',
    '🔑': '',
    '📝': '',
    '💰': '',
    '🏗️': '',
    '🎉': '',
    '📈': '',
    '🔐': '',
    '⏱️': '',
    '📦': '',
    '🎓': '',
    '🌍': '',
    '💾': '',
    '🔥': '',
    '⭐': '',
    '👥': '',
    '🎪': '',
    '🔧': '',
    '📡': '',
    '🏆': '',
    '💬': '',
    '🎮': '',
    '🛡️': '',
    '🟢': '[LOW]',
    '🟡': '[MEDIUM]',
    '🟠': '[HIGH]',
    '🟣': '[MEDIUM]',
    '🔴': '[CRITICAL]',
    '✓': '[✓]',
    '☐': '[ ]',
    '🔔': '',
}

def remove_emojis(text):
    """Remove emojis from text with contextual replacement."""
    # First, replace known emojis with contextual text
    for emoji, replacement in EMOJI_REPLACEMENTS.items():
        text = text.replace(emoji, replacement)
    
    # Then remove any remaining emojis using regex patterns
    for pattern in EMOJI_PATTERNS:
        text = re.sub(pattern, '', text)
    
    # Clean up extra spaces
    text = re.sub(r'  +', ' ', text)
    text = re.sub(r'^\s+$', '', text, flags=re.MULTILINE)
    
    return text

def process_file(file_path):
    """Process a single file to remove emojis."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        content = remove_emojis(content)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Main function to process all markdown files."""
    root_dir = Path(__file__).parent
    
    # Files to process
    files_to_process = [
        'ABOUT_PROJECT.md',
        'README.md',
        'QUICK_START.md',
        'docs/USER_GUIDE.md',
        'docs/API_DOCUMENTATION.md',
        'docs/ARCHITECTURE.md',
        'docs/DEPLOYMENT_GUIDE.md',
        'docs/FRAMEWORKS_REFERENCE.md',
        'todo.md',
    ]
    
    processed = 0
    total = 0
    
    print("=" * 70)
    print("REMOVING EMOJIS FROM DOCUMENTATION")
    print("=" * 70)
    
    for file_path in files_to_process:
        full_path = root_dir / file_path
        if full_path.exists():
            total += 1
            print(f"\nProcessing: {file_path}")
            if process_file(full_path):
                processed += 1
                print(f"  [✓] Emojis removed")
            else:
                print(f"  [ ] No emojis found")
        else:
            print(f"\nSkipping: {file_path} (not found)")
    
    print("\n" + "=" * 70)
    print(f"COMPLETE: {processed} of {total} files updated")
    print("=" * 70)

if __name__ == "__main__":
    main()
