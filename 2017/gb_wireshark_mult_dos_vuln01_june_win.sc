CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811070" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-9352", "CVE-2017-9351", "CVE-2017-9346", "CVE-2017-9345", "CVE-2017-9349", "CVE-2017-9350", "CVE-2017-9344", "CVE-2017-9343", "CVE-2017-9354" );
	script_bugtraq_id( 98804, 98808, 98799, 98798, 98803, 98806, 98796, 98797, 98802 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-02 15:48:52 +0530 (Fri, 02 Jun 2017)" );
	script_name( "Wireshark Multiple Denial-of-Service Vulnerabilities-01 June17 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the epan/dissectors/packet-rgmp.c script within the RGMP
    dissector which could crash.

  - An error in the epan/dissectors/packet-msnip.c script within the MSNIP
    dissector which misuses a NULL pointer.

  - An error in the epan/dissectors/packet-btl2cap.c script within the Bluetooth
    L2CAP dissector which could divide by zero.

  - An error in the epan/dissectors/packet-opensafety.c script within the openSAFETY
    dissector which could crash or exhaust system memory.

  - An error in the epan/dissectors/packet-dcm.c script within the DICOM dissector
    which could go into an infinite loop.

  - An error in the epan/dissectors/packet-slsk.c script within the SoulSeek
    dissector which could go into an infinite loop.

  - An error in the epan/dissectors/packet-dns.c script within the DNS dissector
    which could go into an infinite loop.

  - An error in epan/dissectors/packet-bzr.c script within the Bazaar dissector
    which could go into an infinite loop.

  - An error in epan/dissectors/packet-bootp.c script within the DHCP dissector
    which could read past the end of a buffer." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to crash wireshark or consume excessive CPU resources." );
	script_tag( name: "affected", value: "Wireshark version 2.2.0 through 2.2.6
  and 2.0.0 through 2.0.12 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.2.7 or
  2.0.13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-32.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-30.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-29.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-28.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-27.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-25.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-26.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-22.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-24.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( IsMatchRegexp( wirversion, "^(2\\.2)" ) && version_is_less( version: wirversion, test_version: "2.2.7" ) ){
	fix = "2.2.7";
}
else {
	if(IsMatchRegexp( wirversion, "^(2\\.0)" ) && version_is_less( version: wirversion, test_version: "2.0.13" )){
		fix = "2.0.13";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

