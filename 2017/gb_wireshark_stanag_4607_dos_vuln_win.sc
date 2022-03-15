CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807399" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-6014" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-02-21 14:26:53 +0530 (Tue, 21 Feb 2017)" );
	script_name( "Wireshark 'STANAG 4607' Capture File Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a crafted or
  malformed STANAG 4607 capture file will cause an infinite loop and memory
  exhaustion. If the packet size field in a packet header is null, the offset
  to read from will not advance, causing continuous attempts to read the same
  zero length packet. This will quickly exhaust all system memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop and consume
  excessive CPU resources, resulting in denial-of-service conditions." );
	script_tag( name: "affected", value: "Wireshark versions 2.2.4 and prior
  on Windows." );
	script_tag( name: "solution", value: "Update to Wireshark 2.2.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://git.net/ml/general/2017-02/msg20415.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13416" );
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
if(version_is_less_equal( version: wirversion, test_version: "2.2.4" )){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.2.5" );
	security_message( data: report );
	exit( 0 );
}

