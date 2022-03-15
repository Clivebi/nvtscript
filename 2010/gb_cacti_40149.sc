CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100639" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)" );
	script_cve_id( "CVE-2010-2092" );
	script_bugtraq_id( 40149 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Cacti 'rra_id' Parameter SQL Injection Vulnerability" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40149" );
	script_xref( name: "URL", value: "http://www.php-security.org/2010/05/13/mops-2010-023-cacti-graph-viewer-sql-injection-vulnerability/index.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_tag( name: "summary", value: "Cacti is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Versions prior to Cacti 0.8.7g are vulnerable." );
	script_tag( name: "solution", value: "Update version 0.8.7g or later." );
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
if(version_is_less( version: vers, test_version: "0.8.7g" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.7g" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

