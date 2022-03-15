if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100057" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-03-17 18:51:21 +0100 (Tue, 17 Mar 2009)" );
	script_bugtraq_id( 33865 );
	script_cve_id( "CVE-2009-0753" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "MLdonkey HTTP Request Arbitrary File Download Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Peer-To-Peer File Sharing" );
	script_dependencies( "mldonkey_www.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 4080 );
	script_mandatory_keys( "MLDonkey/www/port/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/33865" );
	script_tag( name: "solution", value: "Fixes are available." );
	script_tag( name: "summary", value: "MLdonkey is prone to a vulnerability that lets attackers download arbitrary
  files. The issue occurs because the application fails to sufficiently sanitize
  user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue will allow an attacker to view arbitrary files within
  the context of the application. Information harvested may aid in launching further attacks." );
	script_tag( name: "affected", value: "MLdonkey 2.9.7 is vulnerable. Other versions may also be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.nongnu.org/mldonkey/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("http_keepalive.inc.sc");
port = get_kb_item( "MLDonkey/www/port/" );
if(isnull( port )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( "//" + file );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(isnull( buf )){
		continue;
	}
	if(egrep( pattern: pattern, string: buf )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
version = get_kb_item( NASLString( "www/", port, "/MLDonkey/version" ) );
if(isnull( version ) || ContainsString( "unknown", version )){
	exit( 0 );
}
if(version <= "2.9.7"){
	info = NASLString( "According to its version number (" );
	info += version;
	info += NASLString( ") MLDonkey is\\nvulnerable, but seems to be reject connections from " );
	info += this_host_name();
	info += NASLString( ".\\n\\n" );
	security_message( port: port, data: info );
	exit( 0 );
}
exit( 99 );

