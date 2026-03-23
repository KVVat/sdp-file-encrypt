#!/usr/bin/env python3
import subprocess
import json
import base64
import sys
import os

if len(sys.argv) < 2:
    print("Usage: ./mcp_extract_screenshot.py <output_file.jpg>")
    sys.exit(1)

out_file = sys.argv[1]

# call get_ui_dump with include_image
proc = subprocess.Popen(["./mcp_call.sh", "get_ui_dump", '{"include_image":true}'], stdout=subprocess.PIPE, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
stdout, _ = proc.communicate()

for line in stdout.split('\n'):
    if line.startswith('data: {'):
        try:
            data = json.loads(line[6:].strip())
            text_str = data['result']['content'][0]['text']
            content_json = json.loads(text_str)
            output_str = content_json.get('output', '{}')
            output_json = json.loads(output_str)
            
            # The MCP server might put the screenshot inside output_json or direct in content_json
            base64_img = None
            if 'screenshot_base64' in output_json:
                base64_img = output_json['screenshot_base64']
            elif 'screenshot' in output_json:
                base64_img = output_json['screenshot']
            elif 'screenshot_base64' in content_json:
                base64_img = content_json['screenshot_base64']
            elif 'screenshot' in content_json:
                base64_img = content_json['screenshot']
                
            if base64_img:
                img_data = base64.b64decode(base64_img)
                with open(out_file, 'wb') as f:
                    f.write(img_data)
                print(f"✅ Successfully saved screenshot to {out_file}")
                sys.exit(0)
        except Exception as e:
            pass

print("❌ Error: Could not find 'screenshot_base64' in the MCP response.")
sys.exit(1)
