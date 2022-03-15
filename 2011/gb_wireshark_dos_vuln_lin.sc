CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801743" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)" );
	script_cve_id( "CVE-2011-0538" );
	script_bugtraq_id( 46167 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Wireshark Denial of Service Vulnerability (Linux)" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_lin.sc" );
	script_mandatory_keys( "Wireshark/Linux/Ver" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/02/04/1" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5652" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a denial
  of service, execution of arbitrary code." );
	script_tag( name: "affected", value: "Wireshark version 1.4.3 and prior Wireshark version 1.5.0" );
	script_tag( name: "insight", value: "The flaw is due to uninitialized pointer during processing of a
  '.pcap' file in the pcap-ng format." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.2.15, 1.4.4 or later." );
	script_tag( name: "summary", value: "The host is installed Wireshark and is prone to Denial of
  Service Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: ver, test_version: "1.4.3" ) || version_is_equal( version: ver, test_version: "1.5.0" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "1.2.15/1.4.4/1.5.1" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

