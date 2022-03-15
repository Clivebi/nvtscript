CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811000" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2016-7958", "CVE-2016-7957" );
	script_bugtraq_id( 93463, 97597 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-17 15:38:00 +0000 (Mon, 17 Apr 2017)" );
	script_tag( name: "creation_date", value: "2017-04-19 14:52:36 +0530 (Wed, 19 Apr 2017)" );
	script_name( "Wireshark Multiple DoS Vulnerabilities-01 Apr17 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to errors in the
  NCP dissector and  Bluetooth L2CAP dissector triggered by packet injection or
  a malformed capture file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause the application to crash resulting in denial-of-service
  condition." );
	script_tag( name: "affected", value: "Wireshark version 2.2.0 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.2.1 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-56.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2016-57.html" );
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
if(wirversion == "2.2.0"){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.2.1" );
	security_message( data: report );
	exit( 0 );
}

