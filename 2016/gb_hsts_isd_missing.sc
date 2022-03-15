if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105877" );
	script_version( "2021-01-26T13:20:44+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-26 13:20:44 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-08-22 13:07:42 +0200 (Mon, 22 Aug 2016)" );
	script_name( "SSL/TLS: `includeSubDomains` Missing in HSTS Header" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_hsts_detect.sc" );
	script_mandatory_keys( "hsts/includeSubDomains/missing/port" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-secure-headers/" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-secure-headers/#http-strict-transport-security-hsts" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc6797" );
	script_xref( name: "URL", value: "https://securityheaders.io/" );
	script_tag( name: "summary", value: "The remote web server is missing the 'includeSubDomains' attribute in the HSTS header." );
	script_tag( name: "solution", value: "Add the 'includeSubDomains' attribute to the HSTS header." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(!port = get_kb_item( "hsts/includeSubDomains/missing/port" )){
	exit( 0 );
}
banner = get_kb_item( "hsts/" + port + "/banner" );
log_message( port: port, data: "The remote web server is missing the \"includeSubDomains\" attribute in the HSTS header.\n\nHSTS Header:\n\n" + banner );
exit( 0 );
