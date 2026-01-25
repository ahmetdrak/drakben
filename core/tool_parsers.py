# Strategy Pattern for Parsers
PARSERS = {
    "nmap": parse_nmap_output,
    "sqlmap": parse_sqlmap_output,
    "nikto": parse_nikto_output,
    # Add new parsers here
}

def parse_tool_output(tool_name: str, output: str, llm_client=None) -> List[Dict]:
    """
    Generic entry point for parsing tool output.
    Selects the correct parser strategy based on tool name.
    """
    parser_func = PARSERS.get(tool_name.lower())
    
    if parser_func:
        return parser_func(output, llm_client) if 'llm_client' in parser_func.__code__.co_varnames else parser_func(output)
        
    # Default/Fallback parser for unknown tools
    logger.warning(f"No specific parser for {tool_name}, returning raw output wrapper")
    return [{"raw_output": output[:500]}]
