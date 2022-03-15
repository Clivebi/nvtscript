if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12295" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0331" );
	script_bugtraq_id( 9750 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Dell OpenManage Web Server <= 3.7.1" );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2004 Tomi Hanninen" );
	script_category( ACT_GATHER_INFO );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 1311 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://sh0dan.org/files/domadv.txt" );
	script_xref( name: "URL", value: "http://support.dell.com/filelib/download.asp?FileID=96563&c=us&l=en&s=DHS&Category=36&OS=WNT5&OSL=EN&SvcTag=&SysID=PWE_FOS_XEO_6650&DeviceID=2954&Type=&ReleaseID=R74029" );
	script_tag( name: "solution", value: "Install the security patch available from Dell." );
	script_tag( name: "summary", value: "Dell OpenManage Web Servers 3.2.0-3.7.1 are vulnerable to a heap based
  buffer overflow attack. A proof of concept denial of service attack has been released." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 1311 );
url = "/servlet/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
if(egrep( pattern: "<br>Version ([0-2]\\.|3\\.[2-6]\\.)|(3\\.7\\.[01])<br>", string: res )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

