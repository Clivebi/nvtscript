CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800041" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685" );
	script_bugtraq_id( 31838 );
	script_name( "Wireshark Multiple Vulnerabilities - Oct08 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_lin.sc" );
	script_mandatory_keys( "Wireshark/Linux/Ver" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2008-06.html" );
	script_tag( name: "impact", value: "Successful attacks may cause the application to crash via specially
  crafted packets." );
	script_tag( name: "affected", value: "Wireshark versions prior to 1.0.4 on Linux." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  a. an error within the Bluetooth ACL dissector, PRP or MATE post dissector.
     Versions 0.99.7 through 1.0.3 are affected by this vulnerability.

  b. an error within the Q.931 dissector. Versions 0.10.3 through 1.0.3
     are affected by this vulnerability.

  c. an uninitialized data structures within the Bluetooth RFCOMM and USB
     Request Block (URB) dissector. Versions 0.99.7 through 1.0.3 are
     affected by this vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Wireshark 1.0.4." );
	script_tag( name: "summary", value: "The Remote host is installed with Wireshark, and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: ver, test_version: "0.99.2", test_version2: "1.0.3" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "1.0.4" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

