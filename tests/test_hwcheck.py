from havokbox import hwcheck

LSUSB_ALL = """Bus 001 Device 002: ID 0e8d:7612 MediaTek Inc. MT7612U 802.11a/b/g/n/ac Wireless Adapter
Bus 001 Device 003: ID 0bda:2838 Realtek Semiconductor Corp. RTL2838 DVB-T
Bus 001 Device 004: ID 10c4:ea60 Silicon Labs CP210x UART Bridge
Bus 001 Device 005: ID 1d50:605b OpenMoko, Inc. RfCat YARD Stick One
Bus 001 Device 006: ID 1546:01a8 U-Blox AG [u-blox 8]
"""


def fake_run(table):
    def run(argv, timeout=10):
        for key, val in table.items():
            if argv[:len(key)] == list(key):
                return val
        return 1, ""
    return run


def by_board(rows):
    return {r["board"].split(" (")[0]: r for r in rows}


def test_everything_working():
    run = fake_run({("lsusb",): (0, LSUSB_ALL),
                    ("rtl_eeprom",): (0, "Found Rafael Micro R828D tuner\nSerial number:\t\t00000001\n"),
                    ("python3", "-c"): (0, ""),
                    ("timeout", "8", "gpspipe"): (0, '{"class":"TPV","device":"/dev/ttyACM0","mode":3}\n')})
    rows = hwcheck.check(run=run, which=lambda b: "/usr/bin/" + b, exists=lambda p: True,
                         wifi_iface=lambda: "wlan1", missing_tools=[])
    b = by_board(rows)
    assert all(r["status"] == "ok" for r in rows), hwcheck.render(rows)
    assert "wlan1" in b["Alfa Wi-Fi"]["detail"] and "00000001" in b["RTL-SDR V3"]["detail"]
    assert b["GPS"]["detail"] == "3D fix"
    assert "CC1101 on SPI" in hwcheck.render(rows)


def test_nothing_plugged_and_missing_software():
    rows = hwcheck.check(run=fake_run({("lsusb",): (0, "")}), which=lambda b: None, exists=lambda p: False,
                         wifi_iface=lambda: None, missing_tools=["air.adsb", "ble.scan"])
    b = by_board(rows)
    for k in ("Alfa Wi-Fi", "RTL-SDR V3", "ZigBee dongle", "Yard Stick One", "GPS"):
        assert b[k]["status"] == "missing" and b[k]["fix"]
    assert b["Software"]["status"] == "check" and "air.adsb" in b["Software"]["detail"]
    assert "Flipper Zero" not in b


def test_needs_attention_cases():
    run = fake_run({("lsusb",): (0, LSUSB_ALL),
                    ("rtl_eeprom",): (1, "usb_claim_interface error -6\n"),
                    ("python3", "-c"): (1, "ModuleNotFoundError"),
                    ("timeout", "8", "gpspipe"): (0, '{"class":"SKY","satellites":[]}\n')})
    flashed = {hwcheck.SNIFFLE_DIR + "/python_cli/sniff_receiver.py"}
    rows = hwcheck.check(run=run, which=lambda b: "/x", exists=lambda p: p in flashed, wifi_iface=lambda: None)
    b = by_board(rows)
    assert b["RTL-SDR V3"]["status"] == "check" and "in use" in b["RTL-SDR V3"]["detail"]
    assert "flash-sniffle" in b["ZigBee dongle"]["fix"]
    assert "rfcat" in b["Yard Stick One"]["fix"]
    assert b["GPS"]["detail"] == "talking to gpsd, no fix yet"
    assert b["Alfa Wi-Fi"]["status"] == "check"
    assert "Software" not in b          # missing_tools=None: not reported


def test_parsers():
    assert hwcheck.usb_ids("Bus 001 Device 003: ID 0BDA:2838 x") == {"0bda:2838"}
    assert hwcheck.gps_fix('{"class":"TPV","mode":1}{"class":"TPV","mode":2}') == "2D"
    assert hwcheck.gps_fix("") is None


def test_wifi_iface_skips_builtin(tmp_path):
    for n in ("eth0", "wlan0", "wlan1"):
        (tmp_path / n).mkdir()
    (tmp_path / "wlan0" / "wireless").mkdir()
    (tmp_path / "wlan1" / "wireless").mkdir()
    assert hwcheck.wifi_monitor_iface(str(tmp_path)) == "wlan1"


def test_two_sdrs_need_distinct_serials():
    two = LSUSB_ALL + "Bus 001 Device 007: ID 0bda:2838 Realtek Semiconductor Corp. RTL2838 DVB-T\n"
    same = fake_run({("lsusb",): (0, two), ("rtl_eeprom",): (0, "Serial number:\t00000001\n")})
    rows = hwcheck.check(run=same, which=lambda b: "/x", exists=lambda p: False, wifi_iface=lambda: None)
    b = by_board(rows)
    assert "RTL-SDR V3 #1" in b and "RTL-SDR V3 #2" in b
    assert "sdr-serials" in b["RTL-SDR pair"]["fix"]

    def run(argv, timeout=10):
        if argv[0] == "lsusb":
            return 0, two
        if argv[0] == "rtl_eeprom":
            return 0, "Serial number:\tHBSDR%d\n" % (int(argv[2]) + 1)
        return 1, ""
    b = by_board(hwcheck.check(run=run, which=lambda b: "/x", exists=lambda p: False, wifi_iface=lambda: None))
    assert "(main)" in b["RTL-SDR V3 #1"]["detail"] and "(aircraft)" in b["RTL-SDR V3 #2"]["detail"]
    assert "RTL-SDR pair" not in b


def test_alfa_ach_is_recognized():
    ls = "Bus 003 Device 110: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac 2T2R DB WLAN Adapter\n"
    rows = hwcheck.check(run=fake_run({("lsusb",): (0, ls)}), which=lambda b: None, exists=lambda p: False,
                         wifi_iface=lambda: None, missing_tools=[])
    alfa = [r for r in rows if r["board"].startswith("Alfa")][0]
    assert alfa["board"] == "Alfa Wi-Fi (AWUS036ACH)" and alfa["status"] == hwcheck.WARN
    assert "rtl88xxau" in alfa["fix"]
