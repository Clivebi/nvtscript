CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100646" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-05-19 12:58:40 +0200 (Wed, 19 May 2010)" );
	script_bugtraq_id( 40106 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-1850" );
	script_name( "Oracle MySQL 'COM_FIELD_LIST' Command Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40106" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html" );
	script_xref( name: "URL", value: "http://bugs.mysql.com/bug.php?id=53237" );
	script_tag( name: "summary", value: "MySQL is prone to a buffer-overflow vulnerability because it fails to
  perform adequate boundary checks on user-supplied data." );
	script_tag( name: "impact", value: "An authenticated attacker can leverage this issue to execute arbitrary
  code within the context of the vulnerable application. Failed exploit
  attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Versions prior to MySQL 5.1.47 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( ver, "^5\\.1\\." ) && version_is_less( version: ver, test_version: "5.1.47" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "5.1.47" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

