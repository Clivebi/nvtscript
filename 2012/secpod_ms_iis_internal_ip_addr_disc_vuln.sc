if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902796" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 3159 );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-23 15:45:49 +0530 (Thu, 23 Feb 2012)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Microsoft IIS IP Address/Internal Network Name Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/834141/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/3159" );
	script_xref( name: "URL", value: "http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q218180" );
	script_xref( name: "URL", value: "http://www.juniper.net/security/auto/vulnerabilities/vuln3159.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "secpod_ms_iis_detect.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain internal IP
  address or internal network name, which could assist in further attacks against the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error while processing 'GET' request. When
  MS IIS receives a GET request without a host header, the Web server will reveal the IP address of the
  server in the content-location field or the location field in the TCP header in the response." );
	script_tag( name: "solution", value: "Apply the hotfix for IIS 6.0" );
	script_tag( name: "summary", value: "The host is running Microsoft IIS Webserver and is prone to
  IP address disclosure vulnerability." );
	script_tag( name: "affected", value: "Microsoft Internet Information Services version 4.0, 5.0, 5.1 and 6.0." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/scripts", "/admin", "/webdav", http_cgi_dirs( port: port ) ) {
	ip = NASLString( "http://", get_host_name(), dir );
	sndReq = NASLString( "GET ", dir, " HTTP/1.0 \\r\\n\\r\\n" );
	rcvRes = http_send_recv( port: port, data: sndReq );
	pattern = NASLString( "Location: ", ip );
	if(rcvRes && ContainsString( rcvRes, pattern ) && egrep( pattern: "^HTTP/.* 302 Object Moved", string: rcvRes )){
		security_message( port );
		exit( 0 );
	}
}

