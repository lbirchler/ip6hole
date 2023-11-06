#!/usr/bin/python3
import os
import subprocess
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

p = Path(__file__).parents[1] / 'src'

def clang_format(fp):
  cmd = f'clang-format -Werror -style=file -i {fp}'
  try: subprocess.check_call(cmd.split())
  except subprocess.CalledProcessError: pass
  return cmd 
      
if __name__ == '__main__':
  files = [
    f for f in p.rglob('*') 
    if f.suffix in ('.h', '.c') and '.output' not in f.parts
  ]

  with ProcessPoolExecutor(max_workers=os.cpu_count()) as exe:
    results = exe.map(clang_format, files)
    print('\n'.join([r for r in results]))
 