CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100271" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-09-07 09:47:24 +0200 (Mon, 07 Sep 2009)" );
	script_bugtraq_id( 36242 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "MySQL 5.x Unspecified Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36242" );
	script_tag( name: "summary", value: "MySQL is prone to a buffer-overflow vulnerability because if fails to
  perform adequate boundary checks on user-supplied data." );
	script_tag( name: "impact", value: "An attacker can leverage this issue to execute arbitrary code within
  the context of the vulnerable application. Failed exploit attempts
  will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "This issue affects MySQL 5.x. Other versions may also be vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
if(version_in_range( version: ver[0], test_version: "5.0", test_version2: "5.1.32" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "Unknown" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

