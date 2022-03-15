if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16101" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2005-0273", "CVE-2005-0274" );
	script_bugtraq_id( 12156, 12157 );
	script_xref( name: "OSVDB", value: "12741" );
	script_xref( name: "OSVDB", value: "12742" );
	script_name( "PhotoPost showgallery.php SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "photopost_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "photopost/detected" );
	script_xref( name: "URL", value: "http://www.gulftech.org/?node=research&article_id=00063-01032005" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "summary", value: "The remote version of PhotoPost PHP contains a vulnerability in the file
  'showgallery.php' which allows a remote attacker to cause the program to
  execute arbitrary SQL statements against the remote database." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
install = get_kb_item( NASLString( "www/", port, "/photopost" ) );
if(isnull( install )){
	exit( 0 );
}
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	loc = matches[2];
	url = NASLString( loc, "/showgallery.php?cat=1'" );
	req = http_get( item: url, port: port );
	r = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(r && ContainsString( r, "SELECT id,catname,description,photos" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

