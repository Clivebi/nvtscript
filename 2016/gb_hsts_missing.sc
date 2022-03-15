if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105879" );
	script_version( "2021-01-26T13:20:44+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-26 13:20:44 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-08-22 13:07:41 +0200 (Mon, 22 Aug 2016)" );
	script_name( "SSL/TLS: HTTP Strict Transport Security (HSTS) Missing" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_hsts_detect.sc" );
	script_mandatory_keys( "hsts/missing/port" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-secure-headers/" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html" );
	script_xref( name: "URL", value: "https://owasp.org/www-project-secure-headers/#http-strict-transport-security-hsts" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc6797" );
	script_xref( name: "URL", value: "https://securityheaders.io/" );
	script_xref( name: "URL", value: "https://httpd.apache.org/docs/current/mod/mod_headers.html#header" );
	script_xref( name: "URL", value: "https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header" );
	script_tag( name: "summary", value: "The remote web server is not enforcing HSTS." );
	script_tag( name: "solution", value: "Enable HSTS or add / configure the required directives correctly following the
  guides linked in the references.

  Note: Some web servers are not sending headers on specific status codes by default. Please review your web server
  or application configuration to always send these headers on every response independently from the status code.

  - Apache: Use 'Header always set' instead of 'Header set'.

  - nginx: Append the 'always' keyword to each 'add_header' directive.

  For different applications or web severs please refer to the related documentation for a similar configuration possibility." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(!port = get_kb_item( "hsts/missing/port" )){
	exit( 0 );
}
max_age_missing = get_kb_item( "hsts/max_age/missing/" + port );
max_age_zero = get_kb_item( "hsts/max_age/zero/" + port );
sts_banner = get_kb_item( "hsts/" + port + "/banner" );
if( max_age_missing ){
	report = "The remote web server is sending a HSTS header but is missing the required 'max-age=' directive.";
	report += "\n\nHSTS-Header:\n\n" + sts_banner;
}
else {
	if( max_age_zero ){
		report = "The remote web server is sending a HSTS header but is defining a 'max-age=0' directive which disables HSTS for this host.";
		report += "\n\nHSTS-Header:\n\n" + sts_banner;
	}
	else {
		banner = get_kb_item( "www/banner/" + port + "/" );
		pattern = "([Dd]ate: |[Ee]xpires=|[Ee]xpires: |PHPSESSID=|[Ll]ast-[Mm]odified: |[Cc]ontent-[Ll]ength: |[Ss]et-[Cc]ookie: |[Ee][Tt]ag: (W/\"|\")?|[Ss]ession[Ii]d=)([0-9a-zA-Z :,-;=]+)";
		if(eregmatch( pattern: pattern, string: banner )){
			banner = ereg_replace( string: banner, pattern: pattern, replace: "\\1***replaced***" );
		}
		report = "The remote web server is not enforcing HSTS.";
		report += "\n\nHTTP-Banner:\n\n" + chomp( banner );
	}
}
log_message( port: port, data: report );
exit( 0 );

