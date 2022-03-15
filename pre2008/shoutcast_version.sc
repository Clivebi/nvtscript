if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10717" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2001-1304" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "SHOUTcast Server DoS detector vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securiteam.com/exploits/5YP031555Q.html" );
	script_tag( name: "summary", value: "This detects SHOUTcast Server's version. If the version equals
  1.8.2 it is vulnerable to a denial of service attack." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest version of SHOUTcast Server." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8000 );
req = "GET /content/nonexistant" + rand() + rand() + rand() + ".mp3 HTTP/1.0\r\n\r\n" + "Host: " + get_host_name() + "\r\n\r\n";
banner = http_keepalive_send_recv( port: port, data: req );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "SHOUTcast Distributed Network Audio Server" )){
	resultrecv = banner;
	resultrecv = strstr( resultrecv, "SHOUTcast Distributed Network Audio Server/" );
	resultsub = strstr( resultrecv, NASLString( "<BR>" ) );
	resultrecv = resultrecv - resultsub;
	resultrecv = resultrecv - "SHOUTcast Distributed Network Audio Server/";
	resultrecv = resultrecv - "<BR>";
	report = NASLString( "The remote SHOUTcast server version is :\\n" );
	report = report + resultrecv;
	if( ContainsString( resultrecv, "1.8.2" ) ){
		report = report + NASLString( "\\n\\nThis version of SHOUTcast is supposedly vulnerable to a denial of service attack. Upgrade your SHOUTcast server.\\n" );
		security_message( port: port, data: report );
	}
	else {
		log_message( port: port, data: report );
	}
}

