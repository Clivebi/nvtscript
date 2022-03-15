CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805392" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-3906", "CVE-2015-3815", "CVE-2015-3813", "CVE-2015-3810", "CVE-2015-3809", "CVE-2015-3808" );
	script_bugtraq_id( 74837, 74630, 74629, 74633, 74632, 74628 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-06-01 17:26:23 +0530 (Mon, 01 Jun 2015)" );
	script_name( "Wireshark Multiple Denial-of-Service Vulnerabilities-01 June15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The 'logcat_dump_text' function in 'wiretap/logcat.c' in the Android
  Logcat file parser  does not properly handle a lack of \\0 termination.

  - The 'detect_version' function in 'wiretap/logcat.c' in the Android Logcat
  file parser does not check the length of the payload.

  - The 'fragment_add_work' function in 'epan/reassemble.c' in the packet-reassembly
  feature does not properly determine the defragmentation state in a case of an
  insufficient snapshot length.

  - 'epan/dissectors/packet-websocket.c' in the WebSocket dissector uses a
  recursive algorithm, which can result in a consumption of CPU resources.

  - The 'dissect_lbmr_pser' function in 'epan/dissectors/packet-lbmr.c' in
  the LBMR dissector does not properly track the current offset and does not
  reject a zero length." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.5
  on Windows" );
	script_tag( name: "solution", value: "Upgrade to version 1.12.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2015-18.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.4" )){
	report = "Installed Version: " + wirversion + "\n" + "Fixed Version:     1.12.5 \n";
	security_message( data: report );
	exit( 0 );
}

