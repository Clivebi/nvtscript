if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.2000099" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-1603" );
	script_bugtraq_id( 9239 );
	script_xref( name: "OSVDB", value: "13295" );
	script_name( "GoAhead WebServer Script Source Code Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "gb_goahead_detect.sc" );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/goahead-adv3.txt" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/975041" );
	script_tag( name: "solution", value: "Upgrade to GoAhead WebServer 2.1.8 or a newer release." );
	script_tag( name: "summary", value: "A vulnerable version of GoAhead Webserver is running on the
  remote host.

  Description :

  GoAhead Webserver is installed on the remote system.
  It's an open-source webserver, which is capable of
  hosting ASP pages, and installation on multiple operating
  systems.

  The version installed is vulnerable to Script Source Code
  Disclosure, by adding extra characters to the URL. Possible
  characters are %00, %5C, %2F." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:embedthis:goahead";
require("host_details.inc.sc");
require("http_func.inc.sc");
func GetFileExt( file ){
	ret = split( buffer: file, sep: "." );
	return ret;
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: port );
banner = http_get_remote_headers( port: port );
host = http_host_name( port: port );
file[0] = "/treeapp.asp";
file[1] = "/default.asp";
if("HTTP/1.0 302" && ContainsString( banner, "Location:" )){
	redirect = egrep( pattern: "^Location:", string: banner );
	rfile = ereg_replace( pattern: "Location: http:\\/\\/+[^/]+", string: redirect, replace: "", icase: TRUE );
	ret = GetFileExt( file: rfile );
	if(!isnull( ret )){
		if(ereg( pattern: "asp", string: ret[1], icase: 1 )){
			file[2] = chomp( rfile );
		}
	}
}
for(n = 0;file[n];n++){
	url = file[n] + "%5C";
	req = NASLString( "GET ", url, " HTTP/1.1", "\\r\\n", "Host: ", host, "\\r\\n\\r\\n" );
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "<% write(HTTP_AUTHORIZATION); %>" ) || ( ContainsString( res, "<%" ) && ( ContainsString( res, "%>" ) ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

