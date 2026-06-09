# cfusa lint

Checks C source files for MISRA-C:2012 and CERT-C coding standard violations.

## Usage

```
cfusa lint [--dir <path>] [--format text|json|sarif|html|md]
           [--output <file>] [--strict] [--list]
```

## Rules

| ID | Standard | Description |
|---|---|---|
| CFUSA-L001 | MISRA-C:2012 R15.5 | Function length exceeds `max_function_lines` |
| CFUSA-L002 | MISRA-C:2012 R15.1 | Use of `goto` |
| CFUSA-L003 | MISRA-C:2012 R21.3 | Dynamic memory (`malloc`/`calloc`/`realloc`/`free`) |
| CFUSA-L004 | MISRA-C:2012 R17.2 | Recursive function call |
| CFUSA-L005 | MISRA-C:2012 R20.5 | Use of `#undef` |
| CFUSA-L006 | MISRA-C:2012 R17.4 | `setjmp`/`longjmp` |
| CFUSA-L007 | MISRA-C:2012 R8.9 | Mutable `static` variable |
| CFUSA-L008 | MISRA-C:2012 R11.5 | `void*` usage |
| CFUSA-L009 | MISRA-C:2012 R20.10 | `#pragma` directive |
| CFUSA-L010 | MISRA-C:2012 R22.8 | `errno` usage pattern |

## Configuration

`max_function_lines` is read from `.cfusa.json` (default: 50).
