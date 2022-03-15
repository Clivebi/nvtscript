if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12049" );
	script_version( "2021-01-20T08:41:35+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 08:41:35 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-1634" );
	script_bugtraq_id( 4874 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Default Novonyx Web Server Files" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Kyger" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Delete the default pages." );
	script_tag( name: "summary", value: "Novell Netware default Novonyx web server files." );
	script_tag( name: "insight", value: "A default installation of Novell 5.x will install the Novonyx web server.
  Numerous web server files included with this installation could reveal system information." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
report = "The following Novonyx web server files were found on the server:\n";
port = http_get_port( default: 80 );
pat1 = "NetBasic WebPro Demo";
pat2 = "Novell";
pat3 = "ScriptEase:WSE";
pat4 = "ALLFIELD.JSE";
pat5 = "LAN Boards";
pat6 = "Media Type";
pat7 = "Login to NDS";
pat8 = "Total Space";
pat9 = "Free Space";
pat10 = "SERVER_SOFTWARE";
pat11 = "GATEWAY_INTERFACE";
pat12 = "ADMSERV_ROOT";
pat13 = "ADMSERV_PWD";
pat14 = "Directory Listing Tool";
pat15 = "Server Name";
pat16 = "Source directory";
pat17 = "secure directories sys";
files = make_list( "/netbasic/websinfo.bas",
	 "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/misc/allfield.jse",
	 "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/misc/test.jse",
	 "/perl/samples/lancgi.pl",
	 "/perl/samples/ndslogin.pl",
	 "/perl/samples/volscgi.pl",
	 "/perl/samples/env.pl",
	 "/nsn/env.bas",
	 "/nsn/fdir.bas" );
for file in files {
	req = http_get( item: file, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(!buf){
		continue;
	}
	if(( ContainsString( buf, pat1 ) && ContainsString( buf, pat2 ) ) || ( ContainsString( buf, pat3 ) && ContainsString( buf, pat4 ) ) || ( ContainsString( buf, pat5 ) && ContainsString( buf, pat6 ) ) || ( ContainsString( buf, pat7 ) && ContainsString( buf, pat2 ) ) || ( ContainsString( buf, pat8 ) && ContainsString( buf, pat9 ) ) || ( ContainsString( buf, pat10 ) && ContainsString( buf, pat11 ) ) || ( ContainsString( buf, pat12 ) && ContainsString( buf, pat13 ) ) || ( ContainsString( buf, pat14 ) && ContainsString( buf, pat15 ) ) || ( ContainsString( buf, pat16 ) && ContainsString( buf, pat17 ) )){
		report += "\n" + file;
		vuln = TRUE;
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

