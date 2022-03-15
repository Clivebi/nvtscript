CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803220" );
	script_version( "2020-12-23T11:09:22+0000" );
	script_cve_id( "CVE-2012-1618" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-12-23 11:09:22 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-01-24 19:16:05 +0530 (Thu, 24 Jan 2013)" );
	script_name( "PostgreSQL JDBC Driver SQL Injection Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2012/Mar/125" );
	script_xref( name: "URL", value: "https://bugzilla.novell.com/show_bug.cgi?id=754273" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2012-03/0126.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/111239/PostgreSQL-JDBC-Driver-8.1-SQL-Injection.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_postgresql_detect_win.sc", "os_detection.sc" );
	script_mandatory_keys( "postgresql/detected", "Host/runs_windows" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information." );
	script_tag( name: "affected", value: "PostgreSQL JDBC Driver versions 8.1 on Windows." );
	script_tag( name: "insight", value: "An error exists within the JDBC driver which fails to escape unspecified
  JDBC statement parameters." );
	script_tag( name: "solution", value: "Upgrade to PostgreSQL JDBC Driver versions 8.2 or later." );
	script_tag( name: "summary", value: "This host is installed with PostgreSQL with JDBC Driver and is
  prone to a SQL injection vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!IsMatchRegexp( vers, "^9\\.1" )){
	exit( 99 );
}
key = "SOFTWARE\\EnterpriseDB\\pgJDBC";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
vers2 = registry_get_sz( key: key, item: "Version" );
if(!vers2){
	exit( 0 );
}
if(version_is_less( version: vers2, test_version: "8.2" )){
	report = report_fixed_ver( installed_version: vers2, fixed_version: "8.2", reg_checked: key + "!Version" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

