if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902568" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)" );
	script_cve_id( "CVE-2009-5099", "CVE-2009-5100", "CVE-2009-5101" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Pentaho BI Server Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37024" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/507168/100/0/threaded" );
	script_xref( name: "URL", value: "http://antisnatchor.com/2009/06/20/pentaho-1701062-multiple-vulnerabilities/" );
	script_xref( name: "URL", value: "http://jira.pentaho.com/browse/BISERVER-2698?page=com.atlassian.jira.plugin.system.issuetabpanels:all-tabpanel" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site or obtain sensitive information." );
	script_tag( name: "affected", value: "Pentaho BI Server version 1.7.0.1062 and prior." );
	script_tag( name: "insight", value: "- Input passed via the 'outputType' parameter to ViewAction is not properly
  sanitised before being returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in
  context of an affected site.

  - Password field with autocomplete enabled, which might allow physically
  proximate attackers to obtain the password.

  - Disclosure of session ID (JSESSIONID) in URL, which allows attackers to
  obtain it from session history, referer headers, or sniffing of web traffic." );
	script_tag( name: "solution", value: "Upgrade to Pentaho BI Server 3.5.0 GA or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running Pentaho BI Server and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = NASLString( "/pentaho/Login" );
res = http_get_cache( item: url, port: port );
if(ContainsString( res, "Pentaho BI Platform" )){
	if(ContainsString( res, "<td colspan=\"2\"><input type=\'password\' name=\'j_password\' size=\"30\" ></td>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}

