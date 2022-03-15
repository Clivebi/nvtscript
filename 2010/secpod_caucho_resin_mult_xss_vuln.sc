if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901115" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)" );
	script_bugtraq_id( 40251 );
	script_cve_id( "CVE-2010-2032" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Caucho Resin Multiple Cross-Site Scripting Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Caucho Technology Resin Professional 3.1.5, 3.1.10 and 4.0.6." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input via the
  'digest_username' and 'digest_realm' parameters in resin-admin/digest.php
  that allows the attackers to insert arbitrary HTML and script code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest version of Caucho Technology Resin Professional 4.0.7." );
	script_tag( name: "summary", value: "The host is running Caucho Resin and is prone to multiple
  cross-site scripting vulnerabilities." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39839" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/511341" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1005-exploits/cauchoresin312-xss.txt" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( item: "/resin-admin/", port: port );
if(ContainsString( res, ">Resin Admin Login<" )){
	url = "/resin-admin/digest.php?digest_attempt=1&digest_realm=\"><script>alert" + "('VT-XSS-Test')</script><a&digest_username[]=";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('VT-XSS-Test'\\)</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
	}
}

