CPE = "cpe:/a:op5:monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103556" );
	script_bugtraq_id( 55191 );
	script_version( "2020-04-22T10:27:30+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:P/A:N" );
	script_name( "op5 Monitor HTML Injection and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55191" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-08-30 10:46:24 +0200 (Thu, 30 Aug 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_op5_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OP5/installed" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
information." );
	script_tag( name: "summary", value: "op5 Monitor is prone to an HTML-injection vulnerability and an
SQL-injection vulnerability because it fails to sanitize user-
supplied input." );
	script_tag( name: "impact", value: "Exploiting these issues may allow an attacker to compromise the
application, access or modify data, exploit vulnerabilities in the
underlying database, execute HTML and script code in the context of
the affected site, steal cookie-based authentication credentials,
or control how the site is rendered to the user, other attacks are
also possible." );
	script_tag( name: "affected", value: "op5 Monitor 5.4.2 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "5.4.2" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "Equal to 5.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

