if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100544" );
	script_version( "$Revision: 11798 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-09 18:37:24 +0200 (Tue, 09 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2010-03-22 19:12:13 +0100 (Mon, 22 Mar 2010)" );
	script_bugtraq_id( 38863 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2010-1191" );
	script_name( "Sahana 'stream.php' Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "sahana_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sahana/detected" );
	script_tag( name: "summary", value: "Sahana is prone to an authentication-bypass vulnerability." );
	script_tag( name: "impact", value: "This issue affects Sahana 0.6.2.2. Other versions may be affected." );
	script_tag( name: "affected", value: "An attacker can exploit this issue to bypass authentication.
  Successful exploits may lead to other attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38863" );
	script_xref( name: "URL", value: "http://www.sahana.lk/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:sahana:sahana";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "0.6.2.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "WillNotFix" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

