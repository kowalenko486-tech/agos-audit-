import asyncio
import json
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

async def run_client():
    print("[KLIENT] Inicjalizacja połączenia Zero-Trust (stdio)...")
    
    # Parametry uruchomienia serwera (uruchamiamy go jako podproces, bez portów)
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "agos.core.mcp_server"],
    )

    # Bezpieczne połączenie z potokami wejścia/wyjścia serwera
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. Inicjalizacja protokołu
            await session.initialize()
            print("[KLIENT] Protokół MCP zainicjowany pomyślnie.")

            # 2. Pobranie listy narzędzi
            tools_response = await session.list_tools()
            tool_names = [t.name for t in tools_response.tools]
            print(f"[KLIENT] Odkryte narzędzia na serwerze: {tool_names}")

            # 3. Wywołanie narzędzia
            print(f"\n[KLIENT] Wywoływanie narzędzia 'system_status'...")
            result = await session.call_tool("system_status", arguments={})

            # 4. Odczyt kryptograficznego dowodu
            print("\n" + "="*50)
            print("--- OTRZYMANY DOWÓD Z SERWERA (EVIDENCE) ---")
            for content in result.content:
                # Formatowanie JSON dla lepszej czytelności w terminalu
                parsed_json = json.loads(content.text)
                print(json.dumps(parsed_json, indent=4, ensure_ascii=False))
            print("="*50 + "\n")

if __name__ == "__main__":
    asyncio.run(run_client())
