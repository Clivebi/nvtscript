CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11378" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 7052 );
	script_cve_id( "CVE-2003-0150" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "MySQL mysqld Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 StrongHoldNet" );
	script_family( "Databases" );
	script_dependencies( "find_service.sc", "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "summary", value: "You are running a version of MySQL which is older than version 3.23.56.
It is vulnerable to a vulnerability that may allow the mysqld service
to start with elevated privileges." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability by creating a DATADIR/my.cnf
that includes the line 'user=root' under the '[mysqld]' option section.

When the mysqld service is executed, it will run as the root
user instead of the default user." );
	script_tag( name: "solution", value: "Upgrade to at least version 3.23.56" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(ereg( pattern: "3\\.(([0-9]\\..*)|(1[0-9]\\..*)|(2(([0-2]\\..*)|3\\.(([0-9]$)|([0-4][0-9])|(5[0-5])))))", string: ver )){
	security_message( port: port );
}

