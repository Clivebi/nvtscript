CPE = "cpe:/a:mariadb:mariadb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808154" );
	script_version( "2019-05-20T11:12:48+0000" );
	script_cve_id( "CVE-2012-5627" );
	script_bugtraq_id( 56837 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "creation_date", value: "2016-06-07 19:33:35 +0530 (Tue, 07 Jun 2016)" );
	script_name( "MariaDB 'COM_CHANGE_USER' Command Insecure Salt Generation Security Bypass Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MariaDB/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "This host is running MariaDB and is
  prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to MariaDB version 5.2.14,
  5.3.12, 5.5.29 or later." );
	script_tag( name: "insight", value: "Flaw that is triggered when a remote
  attacker attempts to login to a user's account via the COM_CHANGE_USER command.
  This command fails to properly disconnect the attacker from the server upon a
  failed login attempt." );
	script_tag( name: "affected", value: "MariaDB versions 5.5.x before 5.5.29,
  5.3.x before 5.3.12, and 5.2.x before 5.2.14 on Linux" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to more easily gain access to a user's account via a brute-force attack." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52015" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Dec/58" );
	script_xref( name: "URL", value: "https://mariadb.atlassian.net/browse/MDEV-3915" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!mariadbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
mariadbVer = get_app_version( cpe: CPE, port: mariadbPort );
if(!mariadbVer || !IsMatchRegexp( mariadbVer, "^5\\.[235]\\." )){
	exit( 0 );
}
if(version_in_range( version: mariadbVer, test_version: "5.2", test_version2: "5.2.13" ) || version_in_range( version: mariadbVer, test_version: "5.3", test_version2: "5.3.11" ) || version_in_range( version: mariadbVer, test_version: "5.5", test_version2: "5.5.28" )){
	fix = "5.2.14, or 5.3.12, or 5.5.29";
	report = report_fixed_ver( installed_version: mariadbVer, fixed_version: fix );
	security_message( port: mariadbPort, data: report );
	exit( 0 );
}
exit( 99 );

