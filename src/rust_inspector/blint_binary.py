import lief
from symbolic._lowlevel import ffi, lib
from symbolic.utils import encode_str, decode_str, rustcall


# TODO: Consider using blint as a dependency instead of vendoring


def demangle_symbolic_name(symbol, lang=None, no_args=False):
    """Demangles symbol using llvm demangle falling back to some heuristics. Covers legacy rust."""
    try:
        func = lib.symbolic_demangle_no_args if no_args else lib.symbolic_demangle
        lang_str = encode_str(lang) if lang else ffi.NULL
        demangled = rustcall(func, encode_str(symbol), lang_str)
        demangled_symbol = decode_str(demangled, free=True).strip()
        # demangling didn't work
        if symbol and symbol == demangled_symbol:
            for ign in ("__imp_anon.", "anon.", ".L__unnamed"):
                if symbol.startswith(ign):
                    return "anonymous"
            if symbol.startswith("GCC_except_table"):
                return "GCC_except_table"
            if symbol.startswith("@feat.00"):
                return "SAFESEH"
            if (
                symbol.startswith("__imp_")
                or symbol.startswith(".rdata$")
                or symbol.startswith(".refptr.")
            ):
                symbol = f"__declspec(dllimport) {symbol.removeprefix('__imp_').removeprefix('.rdata$').removeprefix('.refptr.')}"
            demangled_symbol = (
                symbol.replace("..", "::")
                .replace("$SP$", "@")
                .replace("$BP$", "*")
                .replace("$LT$", "<")
                .replace("$u5b$", "[")
                .replace("$u7b$", "{")
                .replace("$u3b$", ";")
                .replace("$u20$", " ")
                .replace("$u5d$", "]")
                .replace("$u7d$", "}")
                .replace("$GT$", ">")
                .replace("$RF$", "&")
                .replace("$LP$", "(")
                .replace("$RP$", ")")
                .replace("$C$", ",")
                .replace("$u27$", "'")
            )
        # In case of rust symbols, try and trim the hash part from the end of the symbols
        if demangled_symbol.count("::") > 2:
            last_part = demangled_symbol.split("::")[-1]
            if len(last_part) == 17:
                demangled_symbol = demangled_symbol.removesuffix(f"::{last_part}")
        return demangled_symbol
    except AttributeError:
        return symbol


def parse_symbols(symbols):
    """
    Parse symbols from a list of symbols.

    Args:
        symbols (it_symbols): A list of symbols to parse.

    Returns:
        tuple[list[dict], str]: A tuple containing the symbols_list and exe_type
    """
    symbols_list = []

    for symbol in symbols:
        try:
            symbol_version = symbol.symbol_version if symbol.has_version else ""
            is_imported = False
            is_exported = False
            if symbol.imported and not isinstance(symbol.imported, lief.lief_errors):
                is_imported = True
            if symbol.exported and not isinstance(symbol.exported, lief.lief_errors):
                is_exported = True
            symbol_name = symbol.demangled_name
            if isinstance(symbol_name, lief.lief_errors):
                symbol_name = demangle_symbolic_name(symbol.name)
            else:
                symbol_name = demangle_symbolic_name(symbol_name)

            symbols_list.append(
                {
                    "name": symbol_name,
                    "type": str(symbol.type).rsplit(".", maxsplit=1)[-1],
                    "value": symbol.value,
                    "visibility": str(symbol.visibility).rsplit(".", maxsplit=1)[-1],
                    "binding": str(symbol.binding).rsplit(".", maxsplit=1)[-1],
                    "is_imported": is_imported,
                    "is_exported": is_exported,
                    "information": symbol.information,
                    "is_function": symbol.is_function,
                    "is_static": symbol.is_static,
                    "is_variable": symbol.is_variable,
                    "version": str(symbol_version),
                }
            )
        except (AttributeError, IndexError, TypeError):
            continue

    return symbols_list