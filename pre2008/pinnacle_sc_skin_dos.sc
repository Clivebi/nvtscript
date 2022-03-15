if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14824" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1699" );
	script_bugtraq_id( 11232 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Pinnacle ShowCenter Skin DoS" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "summary", value: "The remote host runs the Pinnacle ShowCenter web based interface.

  The remote version of this software is vulnerable to a remote denial of
  service due to a lack of sanity checks on skin parameter." );
	script_tag( name: "impact", value: "With a specially crafted URL, an attacker can deny service of the
  ShowCenter web based interface." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8000 );
url = "/ShowCenter/SettingsBase.php?Skin=ATKvttest";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!res){
	exit( 0 );
}
if(egrep( pattern: "Fatal error.*loaduserprofile.*Failed opening required", string: res )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

