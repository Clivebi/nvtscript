if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801746" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-7271" );
	script_name( "Eclipse IDE Help Contents Multiple Cross-site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://r00tin.blogspot.com/2008/04/eclipse-local-web-server-exploitation.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected application." );
	script_tag( name: "insight", value: "- Input passed to the 'searchWord' parameter in 'help/advanced/searchView.jsp' and
  'workingSet' parameter in 'help/advanced/workingSetManager.jsp' are not
  properly sanitised before being returned to the user." );
	script_tag( name: "summary", value: "This host is running Eclipse IDE is prone to multiple Cross-Site
  Scripting vulnerabilities." );
	script_tag( name: "affected", value: "Eclipse IDE Version 3.3.2." );
	script_tag( name: "solution", value: "Upgrade to Eclipse IDE Version 3.6.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/help/index.jsp", port: port );
if(ContainsString( res, "<title>Help - Eclipse" )){
	vt_strings = get_vt_strings();
	url = "/help/advanced/searchView.jsp?searchWord=a\");}alert" + "(\"" + vt_strings["lowercase"] + "\");</script>";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "alert(\"" + vt_strings["lowercase"] + "\");</script>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

