CPE = "cpe:/a:firestats:firestats";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100227" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-06-21 16:51:00 +0200 (Sun, 21 Jun 2009)" );
	script_cve_id( "CVE-2009-2143" );
	script_bugtraq_id( 35367 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "FireStats 'firestats-wordpress.php' Remote File Include Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "firestats_detect.sc" );
	script_mandatory_keys( "firestats/installed" );
	script_tag( name: "solution", value: "The vendor has released 'FireStats 1.6.2' to address this issue." );
	script_tag( name: "summary", value: "FireStats is prone to a remote file-include vulnerability because it fails to
  sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to compromise the application and
  the underlying system, other attacks are also possible." );
	script_tag( name: "affected", value: "FireStats 1.6.1 is vulnerable, prior versions may also be affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35367" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

