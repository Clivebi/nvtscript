CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801380" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)" );
	script_cve_id( "CVE-2010-2008" );
	script_bugtraq_id( 41198 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_name( "MySQL 'ALTER DATABASE' Remote Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40333" );
	script_xref( name: "URL", value: "http://bugs.mysql.com/bug.php?id=53804" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Jun/1024160.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-48.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to cause a Denial of Service." );
	script_tag( name: "affected", value: "MySQL version priot to 5.1.48 on all running platform." );
	script_tag( name: "solution", value: "Upgrade to MySQL version 5.1.48." );
	script_tag( name: "summary", value: "The host is running MySQL and is prone to Denial Of Service
  vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing the 'ALTER DATABASE' statement and
  can be exploited to corrupt the MySQL data directory using the '#mysql50#'
  prefix followed by a '.' or '..'.

  NOTE: Successful exploitation requires 'ALTER' privileges on a database." );
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
	if(version_is_less( version: mysqlVer[1], test_version: "5.1.48" )){
		report = report_fixed_ver( installed_version: mysqlVer[1], fixed_version: "5.1.48" );
		security_message( port: sqlPort, data: report );
	}
}

