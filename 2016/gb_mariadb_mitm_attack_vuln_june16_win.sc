CPE = "cpe:/a:mariadb:mariadb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808065" );
	script_version( "2019-07-05T09:12:25+0000" );
	script_cve_id( "CVE-2015-3152" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-06-02 18:10:39 +0530 (Thu, 02 Jun 2016)" );
	script_name( "MariaDB Man-in-the-Middle Attack Vulnerability - Jun16 (Windows)" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MariaDB/installed", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://jira.mariadb.org/browse/MDEV-7937" );
	script_xref( name: "URL", value: "https://bugzilla.suse.com/show_bug.cgi?id=924663" );
	script_tag( name: "summary", value: "This host is running MariaDB and is prone
  to man-in-the-middle attack vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to use of improper --ssl
  option when establishing a secure connection." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  man-in-the-middle attackers to spoof servers via a cleartext-downgrade
  attack." );
	script_tag( name: "affected", value: "MariaDB version 5.5.43 and earlier
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to version MariaDB 5.5.44 or
  later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!mariadbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mariadbVer = get_app_version( cpe: CPE, port: mariadbPort )){
	exit( 0 );
}
if(version_is_less( version: mariadbVer, test_version: "5.5.44" )){
	report = report_fixed_ver( installed_version: mariadbVer, fixed_version: "5.5.44" );
	security_message( data: report, port: mariadbPort );
	exit( 0 );
}
exit( 99 );

