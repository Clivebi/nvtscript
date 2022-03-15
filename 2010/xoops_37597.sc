CPE = "cpe:/a:xoops:xoops";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100422" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-01-05 18:50:28 +0100 (Tue, 05 Jan 2010)" );
	script_bugtraq_id( 37597 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "XOOPS 'include/notification_update.php' SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_xoops_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "XOOPS/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37597" );
	script_xref( name: "URL", value: "http://www.xoops.org/modules/news/article.php?storyid=5178" );
	script_xref( name: "URL", value: "http://www.xoops.org" );
	script_tag( name: "summary", value: "XOOPS is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an
  SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database." );
	script_tag( name: "affected", value: "Versions prior to XOOPS 2.4.3 are affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less( version: vers, test_version: "2.4.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

