CPE = "cpe:/a:tutos:tutos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14793" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10129 );
	script_xref( name: "OSVDB", value: "5326" );
	script_cve_id( "CVE-2003-0481", "CVE-2003-0482" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Tutos input validation Issues" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_tutos_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "tutos/installed" );
	script_tag( name: "solution", value: "Upgrade to Tutos-1.1.20040412 or newer" );
	script_tag( name: "summary", value: "The remote host is running Tutos, an open-source team organization software
 package written in PHP.

 The remote version of this software is vulnerable to multiple input validation
 flaws which may allow an authenticated user to perform a cross site scripting
 attack, path disclosure attack or a SQL injection against the remote service." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(egrep( pattern: "(0\\..*|1\\.(0\\.|1\\.(2003|20040[1-3]|2004040[0-9]|2004041[01])))", string: vers )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

