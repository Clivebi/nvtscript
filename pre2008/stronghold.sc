if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10803" );
	script_version( "2021-02-26T10:28:36+0000" );
	script_tag( name: "last_modification", value: "2021-02-26 10:28:36 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2001-0868" );
	script_bugtraq_id( 3577 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Redhat Stronghold Secure Server File System Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Felix Huber" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "In Redhat Stronghold from versions 2.3 up to 3.0 a flaw
  exists that allows a remote attacker to disclose sensitive system files including the
  httpd.conf file, if a restricted access to the server status report is not enabled when
  using those features." );
	script_tag( name: "impact", value: "This may assist an attacker in performing further attacks.

  By trying the following URLs, an attacker can gather sensitive information:

  http://example.com/stronghold-info will give information on configuration

  http://example.com/stronghold-status will return among other information the list of
  request made

  Please note that this attack can be performed after a default installation. The
  vulnerability seems to affect all previous version of Stronghold." );
	script_tag( name: "solution", value: "The vendor has released an update on November 19, 2001." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/stronghold-info";
res = http_get_cache( item: url, port: port );
if(res && ContainsString( res, "Stronghold Server Information" )){
	VULN = TRUE;
	report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
url = "/stronghold-status";
res = http_get_cache( item: url, port: port );
if(res && ContainsString( res, "Stronghold Server Status for" )){
	VULN = TRUE;
	report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
if(VULN){
	security_message( port: port, data: "The following URLs are exposed:" + report );
	exit( 0 );
}
exit( 99 );

