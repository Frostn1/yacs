from src.yacs_search import YACSSearch


def display_search(search: YACSSearch) -> None:
    """Display the search matches."""
    print()
    print(f'{'Now showing matches': ^100}')
    print(f"[Vendor] {search.query.vendor}", end="\t")
    print(f"[Product] {search.query._product}", end="\t")
    print(f"[Version] {search.query.version}", end="\t")
    print()

    check = True
    for match in search.matches:
        if check:
            command = input(
                "Press enter to coninue... (q to quit, c to not stop after each cve): "
            )
        match command:
            case "q":
                break
            case "c":
                check = False
        print()
        print(f"{match.cve['cve']['CVE_data_meta']['ID']:=^100}")
        print()
        match.pretty_print()
        print()
