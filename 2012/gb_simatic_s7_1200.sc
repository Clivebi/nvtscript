CPE = "cpe:/a:siemens:simatic_s7_1200";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103571" );
	script_bugtraq_id( 55559 );
	script_cve_id( "CVE-2012-3037" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 11855 $" );
	script_name( "Siemens SIMATIC S7-1200 SSL Private Key Reuse Spoofing Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55559" );
	script_xref( name: "URL", value: "http://subscriber.communications.siemens.com/" );
	script_xref( name: "URL", value: "http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-240718.pdf" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-20 10:18:56 +0200 (Thu, 20 Sep 2012)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_simatic_s7_version.sc" );
	script_mandatory_keys( "simatic_s7/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Siemens SIMATIC S7-1200 is prone to a security vulnerability that may
 allow attackers to spoof SSL certificates.

 Attackers can exploit this issue to display incorrect SSL
 certificates. Successful exploits will cause victims to accept the
 certificates assuming they are from a legitimate site.

 Siemens SIMATIC S7-1200 versions 2.x are vulnerable. Other versions
 may also be affected." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\." )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

