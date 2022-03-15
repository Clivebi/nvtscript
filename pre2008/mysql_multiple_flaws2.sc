CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15449" );
	script_version( "$Revision: 11556 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 17:37:40 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 11357 );
	script_cve_id( "CVE-2004-0835", "CVE-2004-0837" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "MySQL multiple flaws (2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "solution", value: "Upgrade to the latest version of MySQL 3.23.59 or 4.0.21 or newer" );
	script_tag( name: "summary", value: "The remote host is running a version of the MySQL database which is
older than 4.0.21 or 3.23.59.

MySQL is a database which runs on both Linux/BSD and Windows platform.
The remote version of this software is vulnerable to specially crafted
ALTER TABLE SQL query which can be exploited to bypass some applied security
restrictions or cause a denial of service.

To exploit this flaw, an attacker would need the ability to execute arbitrary
SQL statements on the remote host." );
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
if(ereg( pattern: "^(3\\.([0-9]\\.|1[0-9]\\.|2[0-2]\\.|23\\.(([0-9]|[1-4][0-9]|5[0-8])[^0-9]))|4\\.0\\.([0-9]|1[0-9]|20)[^0-9])", string: ver )){
	security_message( port );
}

