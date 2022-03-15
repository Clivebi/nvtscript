if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105623" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-04-26 13:10:26 +0200 (Tue, 26 Apr 2016)" );
	script_name( "Cisco Finesse Detect" );
	script_tag( name: "summary", value: "This script performs ssh based detection of Cisco Finesse" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cisco/finesse/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
if(!get_kb_item( "cisco/finesse/detected" )){
	exit( 0 );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
show_ver = ssh_cmd( socket: sock, cmd: "show version active", nosh: TRUE, pty: TRUE, timeout: 60, retry: 30, pattern: "Active Master Version:" );
if(!show_ver || !ContainsString( show_ver, "Active Master Version:" )){
	exit( 0 );
}
cpe = "cpe:/a:cisco:finesse";
vers = "unknown";
version = eregmatch( pattern: "Active Master Version: ([^\r\n]+)", string: show_ver );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "cisco/finesse/version", value: vers );
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: "ssh" );
log_message( data: build_detection_report( app: "Cisco Finesse", version: vers, install: "ssh", cpe: cpe, concluded: "show version active" ), port: 0 );
exit( 0 );

