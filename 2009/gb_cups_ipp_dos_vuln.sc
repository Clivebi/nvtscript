CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800581" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-0949" );
	script_bugtraq_id( 35169 );
	script_name( "CUPS IPP Packets Processing Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/AppleCUPS-null-pointer-vulnerability" );
	script_tag( name: "impact", value: "An attacker can exploit will allow application to crash." );
	script_tag( name: "affected", value: "CUPS version prior to 1.3.10." );
	script_tag( name: "insight", value: "The flaw is cause due to a NULL-pointer dereference that occurs when
  processing two consecutive IPP_TAG_UNSUPPORTED tags in specially
  crafted IPP (Internet Printing Protocol) packets." );
	script_tag( name: "solution", value: "Upgrade to version 1.3.10 or later." );
	script_tag( name: "summary", value: "This host is running CUPS, and is prone to Denial of Service
  Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!IsMatchRegexp( vers, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.3.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

