CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811800" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_cve_id( "CVE-2017-13764" );
	script_bugtraq_id( 100545 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-05 16:13:23 +0530 (Tue, 05 Sep 2017)" );
	script_name( "Wireshark 'Modbus' Dissector DoS Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a NULL pointer
  dereference error in 'epan/dissectors/packet-mbtcp.c' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to make Wireshark crash by injecting a malformed packet onto
  the wire or by convincing someone to read a malformed packet trace file." );
	script_tag( name: "affected", value: "Wireshark version 2.4.0 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.4.1 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-40.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(wirversion == "2.4.0"){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.4.1" );
	security_message( data: report );
	exit( 0 );
}

