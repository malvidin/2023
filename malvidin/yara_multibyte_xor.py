import re
from binascii import hexlify

input_1 = r'Software\Microsoft\Windows\CurrentVersion\Run'
input_2 = r'https://github.com/100DaysofYARA'


blank16 = '''
rule {title}_2byte
{{
  meta:
    author = "malvidin"
    description = "Look for two byte xor of target string. Creating ~64K separate rules is faster (~12MB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "{target_string}"

  strings:
    $target_string = /{target_escaped}/

  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : (
      {xor_compare}
      and console.hex("{title} target string found at ", i)  
    )
}}
'''

blank24 = '''
rule {title}_3byte 
{{
  meta:
    author = "malvidin"
    description = "Look for three byte xor of target string. Creating ~16M separate rules would probably be faster (~3.2 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "{target_string}"

  strings:
    $target_string = /{target_escaped}/

  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : (
      {xor_compare}
      and console.hex("{title} target string found at ", i)  
    )
}}
'''

blank32 = '''
rule {title}_4byte 
{{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "{target_string}"

  strings:
    $target_string = /{target_escaped}/

  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : (
      {xor_compare}
      and console.hex("{title} target string found at ", i)  
    )
}}
'''

d = {
    2: blank16,
    3: blank24,
    4: blank32,
}


def generate_rules(input_string, title, out_file=None):
    input_bytes = input_string.encode('utf-8')
    if len(input_bytes) < 12:
        print('input is not long enough')
        return
    if out_file is not None:
        with open(out_file, 'w') as yf:
            yf.write('import "console"\n')
    for i in (2, 3, 4):
        xor_list = []
        for j in range(0, len(input_bytes), i):
            if len(input_bytes[j + i:j + 2 * i]) < i:
                break
            xor_bytes = bytes(a ^ b for a, b in zip(input_bytes[j:j + i], input_bytes[j + i:j + 2 * i]))
            xor_str = '0x' + hexlify(xor_bytes).decode('latin1')
            if i == 2:
                xor_list.append(f'( uint16be(i+{j}) ^ uint16be(i+{i+j}) ) == {xor_str}')
            if i == 3:
                xor_list.append(f'( ( uint32be(i+{j}) ^ uint32be(i+{i+j}) ) >> 8 ) == {xor_str}')
            if i == 4:
                xor_list.append(f'( uint32be(i+{j}) ^ uint32be(i+{i+j}) ) == {xor_str}')
        yr = d[i].format(
            title=title,
            target_string=input_string.replace('\\', '\\\\'),
            target_escaped=re.escape(input_string).replace('/', '\\/'),
            xor_compare=' and \n      '.join(xor_list),
        )
        if out_file is None:
            print(yr)
        else:
            with open(out_file, 'a') as yf:
                yf.write(yr)


generate_rules(input_1, "current_version", 'current_version.yara')
generate_rules(input_2, "days_of_yara_url",  '100_days_of_yara.yara')
