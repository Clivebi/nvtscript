CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809803" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-9374", "CVE-2016-9376", "CVE-2016-9373", "CVE-2016-9375" );
	script_bugtraq_id( 94369 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-11-18 12:48:21 +0530 (Fri, 18 Nov 2016)" );
	script_name( "Wireshark Multiple Denial of Service Vulnerabilities Nov16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The AllJoyn dissector could crash with a buffer over-read, triggered by
    network traffic or a capture file.

  - The DCERPC dissector could crash with a use-after-free, triggered by network
    traffic or a capture file.

  - The DTN dissector could go into an infinite loop, triggered by network
    traffic or a capture file.

  - The OpenFlow dissector could crash with memory exhaustion, triggered by network
    traffic or a capture file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 2.2.0 to 2.2.1 and
  2.0.0 to 2.0.7 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.2.2 or
  or 2.0.8 later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-59.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-60.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-61.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-62.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( version_in_range( version: wirversion, test_version: "2.0.0", test_version2: "2.0.7" ) ){
	fix = "2.0.8";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wirversion, test_version: "2.2.0", test_version2: "2.2.1" )){
		fix = "2.2.2";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

