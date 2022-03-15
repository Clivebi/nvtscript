CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100900" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-11-10 13:18:12 +0100 (Wed, 10 Nov 2010)" );
	script_bugtraq_id( 43676 );
	script_cve_id( "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Oracle MySQL Prior to 5.1.51 Multiple Denial Of Service Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43676" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-51.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "summary", value: "MySQL is prone to multiple denial-of-service vulnerabilities." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to crash the database, denying
access to legitimate users." );
	script_tag( name: "affected", value: "These issues affect versions prior to MySQL 5.1.51." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	exit( 0 );
}
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: ver, test_version: "5", test_version2: "5.1.50" )){
	report = report_fixed_ver( installed_version: ver, vulnerable_range: "5 - 5.1.50" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

