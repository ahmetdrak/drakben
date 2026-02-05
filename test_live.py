"""Live functionality test."""

import asyncio

from core.tools.tool_registry import get_registry


async def main():
    print("=== GERÇEK FONKSİYONEL TEST ===\n")
    registry = get_registry()

    # 1. Python tool test - passive_recon
    print("1. passive_recon (Python tool):")
    try:
        result = await registry.run("passive_recon", target="example.com")
        print(f"   Success: {result.get('success')}")
        if result.get("output"):
            print(f"   Output type: {type(result.get('output'))}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # 2. sqli_test
    print("\n2. sqli_test (Python tool):")
    try:
        result = await registry.run("sqli_test", target="http://example.com/test?id=1")
        print(f"   Success: {result.get('success')}")
        print(f"   Error: {result.get('error', 'None')[:80] if result.get('error') else 'None'}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # 3. xss_test
    print("\n3. xss_test (Python tool):")
    try:
        result = await registry.run("xss_test", target="http://example.com")
        print(f"   Success: {result.get('success')}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # 4. Check tool info
    print("\n4. Tool Types:")
    for name in ["nmap", "passive_recon", "sqli_test"]:
        tool = registry.get(name)
        if tool:
            print(f"   {name}: {tool.type.value} - {tool.description[:40]}...")

    # 5. Direct module import test
    print("\n5. Direct Module Test:")
    try:
        from modules.recon import passive_recon

        data = await passive_recon("google.com")
        print(f"   passive_recon keys: {list(data.keys())}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # 6. Exploit module
    print("\n6. Exploit Module Test:")
    try:
        from modules.exploit import AIEvasion, PolyglotEngine

        payloads = PolyglotEngine.get_chimera_payloads()
        mutations = AIEvasion.mutate_payload("<script>alert(1)</script>")
        print(f"   Polyglots: {len(payloads)}, Mutations: {len(mutations)}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # 7. C2 module
    print("\n7. C2 Module Test:")
    try:
        from modules.c2_framework import C2Channel, C2Config, C2Protocol

        config = C2Config(
            primary_host="test.local",
            protocol=C2Protocol.HTTPS,
        )
        c2 = C2Channel(config=config)
        print(f"   C2Channel created, host: {c2.config.primary_host}")
    except Exception as e:
        print(f"   ERROR: {e}")

    print("\n=== TEST TAMAMLANDI ===")


if __name__ == "__main__":
    asyncio.run(main())
