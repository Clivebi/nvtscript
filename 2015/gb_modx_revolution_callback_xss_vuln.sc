if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805235" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-8992" );
	script_bugtraq_id( 71821 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-01-07 14:55:47 +0530 (Wed, 07 Jan 2015)" );
	script_name( "MODX Revolution 'callback' Parameter Cross-Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_modx_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "modx_cms/installed" );
	script_xref( name: "URL", value: "https://github.com/modxcms/revolution/issues/12161" );
	script_tag( name: "summary", value: "This host is installed with MODX
  Revolution and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Check the md5sum of the affected
  .swf files" );
	script_tag( name: "insight", value: "The error exists because the
  /manager/assets/fileapi/FileAPI.flash.image.swf script does not
  validate input to the 'callback' parameter before returning it to
  users." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to execute arbitrary HTML and script code in a
  users browser session in the context of an affected site." );
	script_tag( name: "affected", value: "MODX Revolution version 2.3.2-pl." );
	script_tag( name: "solution", value: "No known solution was made available for at
  least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
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
if(dir == "/"){
	dir = "";
}
url = dir + "/manager/assets/fileapi/FileAPI.flash.image.swf";
md5File = "ca807df6aa04b87a721239e38bf2e9e1";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(isnull( res )){
	exit( 0 );
}
resmd5 = hexstr( MD5( res ) );
if(resmd5 == md5File){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

