if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14312" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 11612 );
	script_name( "ScanMail file check" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2004 by DokFLeed" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script attempts to read sensitive files used by Trend
  ScanMail, an anti-virus protection program for Domino (formerly Lotus Notes)." );
	script_tag( name: "impact", value: "An attacker, exploiting this flaw, may gain access to confidential
  data or disable the anti-virus protection." );
	script_tag( name: "solution", value: "Password protect access to these files." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
files = make_array( "/smency.nsf", "Encyclopedia", "/smconf.nsf", "Configuration", "/smhelp.nsf", "Help", "/smftypes.nsf", "File Types", "/smmsg.nsf", "Messages", "/smquar.nsf", "Quarantine", "/smtime.nsf", "Scheduler", "/smsmvlog.nsf", "Log", "/smadmr5.nsf", "Admin Add-in" );
report = "";
for path in keys( files ) {
	req = http_get( item: path, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(ContainsString( res, "Trend ScanMail" )){
		if(!report){
			report = "The following files were found:";
		}
		report += NASLString( "\\n    ", path, " - ", files[path] );
	}
}
if(report){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

