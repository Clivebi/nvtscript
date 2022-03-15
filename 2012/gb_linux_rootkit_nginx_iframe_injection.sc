CPE = "cpe:/a:nginx:nginx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802045" );
	script_version( "2021-01-29T11:29:20+0000" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-01-29 11:29:20 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "creation_date", value: "2012-12-03 13:43:19 +0530 (Mon, 03 Dec 2012)" );
	script_name( "64-bit Debian Linux Rootkit with nginx Doing iFrame Injection" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Nov/94" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Nov/172" );
	script_xref( name: "URL", value: "http://blog.crowdstrike.com/2012/11/http-iframe-injecting-linux-rootkit.html" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/blog/208193935/New_64_bit_Linux_Rootkit_Doing_iFrame_Injections" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Malware" );
	script_dependencies( "gb_nginx_consolidation.sc" );
	script_mandatory_keys( "nginx/http/detected" );
	script_tag( name: "impact", value: "Successful iframe injection leads redirecting to some malicious sites." );
	script_tag( name: "affected", value: "64-bit Debian Squeeze (kernel version 2.6.32-5-amd64) with nginx." );
	script_tag( name: "insight", value: "64-bit Debian Squeeze Linux Rootkit in combination with nginx launching
  iframe injection attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Debian Squeeze Linux Rootkit with nginx and
  is prone to iframe injection." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
bad_req = NASLString( "GET / HTTP/1.1\\r\\n", "Hostttt ", get_host_name(), "\\r\\n\\r\\n" );
bad_res = http_keepalive_send_recv( port: port, data: bad_req );
if(ContainsString( bad_res, "HTTP/1.1 400 Bad Request" ) && ContainsString( bad_res, "Server: nginx" ) && egrep( pattern: "<iframe\\s+src=.*</iframe>", string: bad_res, icase: TRUE )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

