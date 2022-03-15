if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803110" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 55767 );
	script_cve_id( "CVE-2012-6534" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-11-23 15:27:29 +0530 (Fri, 23 Nov 2012)" );
	script_name( "Novell Sentinel Log Manager Retention Policy Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50797/" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2012-10/0026.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions." );
	script_tag( name: "affected", value: "Novell Sentinel Log Manager version 1.2.0.2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error when saving a retention policy and can be
  exploited by a report administrator (read only role) to create new policies." );
	script_tag( name: "solution", value: "Apply the patch or upgrade to 1.2.0.3 or later." );
	script_tag( name: "summary", value: "The host is running Novell Sentinel Log Manager and is prone security bypass
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8443 );
host = http_host_name( port: port );
req1 = http_get( item: "/novelllogmanager/views/logon.html", port: port );
res1 = http_keepalive_send_recv( port: port, data: req1 );
if(res1 && ContainsString( res1, ">Novell Sentinel Log Manager" ) && ContainsString( res1, ">Novell Identity Audit<" )){
	post_data = "5|0|9|https://" + host + "/novelllogmanager/" + "com.novell.siem.logmanager.LogManager/|E377321CAAD2FABED6" + "283BD3643E4289|com.novell.sentinel.scout.client.about.Abo" + "utLogManagerService|getLogManagerInfo|1|2|3|4|0|";
	req2 = NASLString( "POST /novelllogmanager/datastorageservice.rpc HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "DNT: n", "Content-Type: text/x-gwt-rpc; charset=utf-8\\r\\n", "Content-Length: ", strlen( post_data ), "\\r\\n", "\\r\\n", post_data );
	res2 = http_keepalive_send_recv( port: port, data: req2 );
	if(ContainsString( res2, "The call" ) && ContainsString( res2, "on the server;" ) && ContainsString( res2, "server log for details" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

