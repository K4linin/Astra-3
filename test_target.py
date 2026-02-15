import sys
import importlib.util

# Load the target module
spec = importlib.util.spec_from_file_location('img2pdf_convert', 'fuzz/targets/img2pdf_convert.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Check if fuzz_target exists
print(f'fuzz_target exists: {hasattr(module, "fuzz_target")}')
if hasattr(module, 'fuzz_target'):
    print(f'fuzz_target type: {type(module.fuzz_target)}')
    print(f'fuzz_target callable: {callable(module.fuzz_target)}')
    
    # Test it
    module.fuzz_target(b'test data')
    print('Test call succeeded!')