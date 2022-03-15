CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805696" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-4652", "CVE-2015-4651" );
	script_bugtraq_id( 75316, 75317 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-07-30 13:20:52 +0530 (Thu, 30 Jul 2015)" );
	script_name( "Wireshark Multiple Denial-of-Service Vulnerabilities-01 July15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The 'epan/dissectors/packet-gsm_a_dtap.c' script in the GSM DTAP dissector
    does not properly validate digit characters.

  - The 'dissect_wccp2r1_address_table_info' function in
    'epan/dissectors/packet-wccp.c' script in the WCCP dissector does not properly
    determine whether enough memory is available for storing IP address strings." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.6
  on Windows" );
	script_tag( name: "solution", value: "Upgrade Wireshark to version 1.12.6 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2015-19.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11201" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11153" );
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
if(version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.5" )){
	report = "Installed Version: " + wirversion + "\n" + "Fixed Version:     1.12.6 \n";
	security_message( data: report );
	exit( 0 );
}

