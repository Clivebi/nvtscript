CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103471" );
	script_bugtraq_id( 51925, 52154 );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-0882" );
	script_name( "MySQL 'yaSSL' Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51925" );
	script_xref( name: "URL", value: "https://lists.immunityinc.com/pipermail/canvas/2012-February/000011.html" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-04-19 11:22:35 +0200 (Thu, 19 Apr 2012)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "summary", value: "MySQL is prone to an unspecified remote code-execution vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this vulnerability to execute arbitrary code in
the context of the affected application." );
	script_tag( name: "insight", value: "Limited information is available regarding this issue. This script will
be updated as more information becomes available." );
	script_tag( name: "affected", value: "MySQL 5.5.20 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "The issues seem to be fixed in MySQL versions 5.5.22 and 5.1.62." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sqlPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mysqlVer = get_app_version( cpe: CPE, port: sqlPort )){
	exit( 0 );
}
mysqlVer = eregmatch( pattern: "([0-9.a-z]+)", string: mysqlVer );
if(!isnull( mysqlVer[1] )){
	if(version_in_range( version: mysqlVer[1], test_version: "5.5", test_version2: "5.5.21" )){
		report = report_fixed_ver( installed_version: mysqlVer[1], vulnerable_range: "5.5.22" );
		security_message( port: sqlPort, data: report );
	}
	if(version_in_range( version: mysqlVer[1], test_version: "5.1", test_version2: "5.1.61" )){
		report = report_fixed_ver( installed_version: mysqlVer[1], vulnerable_range: "5.1.62" );
		security_message( port: sqlPort, data: report );
	}
}

