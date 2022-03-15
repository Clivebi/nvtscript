CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100147" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_bugtraq_id( 33858 );
	script_cve_id( "CVE-2009-1211" );
	script_name( "Squid information-disclosure vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_require_ports( "Services/http_proxy", 3128, "Services/www", 8080 );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "According to its version number, the remote version of Squid is prone to an
  information-disclosure vulnerability related to the interpretation of the Host HTTP header. Specifically,
  this issue occurs when the proxy makes a forwarding decision based on the Host HTTP header instead of the destination
  IP address." );
	script_tag( name: "impact", value: "Attackers may exploit this issue to obtain sensitive information such as
  internal intranet webpages. Additional attacks may also be possible." );
	script_tag( name: "affected", value: "These issues affect Squid 2.7 and 3.0." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(egrep( pattern: "(2\\.7|3\\.0)", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Unknown" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

