if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117497" );
	script_version( "2021-06-16T13:40:04+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-16 13:40:04 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-16 11:36:51 +0000 (Wed, 16 Jun 2021)" );
	script_name( "CKEditor / FCKeditor 'uploadtest.html' SSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_ckeditor_http_detect.sc", "gb_fckeditor_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ckeditor_or_fckeditor/http/detected" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/50021" );
	script_tag( name: "summary", value: "The 'uploadtest.html' file shipped with CKEditor / FCKeditor is
  prone to a server-side request forgery (SSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks via a crafted HTTP GET request if the affected
  uploadtest.html file exists on the target host." );
	script_tag( name: "impact", value: "This flaw may allow an unauthenticated attacker to send
  unauthorized requests from the target host to external and internal systems, potentially leading
  to network enumeration or facilitating other attacks." );
	script_tag( name: "affected", value: "CKEditor version 3.x and FCKeditor version 2.x are known to
  ship the vulnerable file." );
	script_tag( name: "solution", value: "Remove the affected file from the target host.

  Note: CKEditor 4.0+ doesn't ship this file anymore but it still might exist on the file system
  if it wasn't removed during the update." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:ckeditor:ckeditor",
	 "cpe:/a:fckeditor:fckeditor" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "www" )){
	exit( 0 );
}
CPE = infos["cpe"];
port = infos["port"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
urls = make_list( dir + "/filemanager/connectors/uploadtest.html",
	 dir + "/editor/filemanager/connectors/uploadtest.html" );
for url in urls {
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<title>FCKeditor - Uploaders Tests</title>" ) || ContainsString( res, "Custom Uploader URL:<BR>" ) || ContainsString( res, "value=\"Send it to the Server\"" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

