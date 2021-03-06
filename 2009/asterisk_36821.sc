CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100319" );
	script_version( "$Revision: 4887 $" );
	script_tag( name: "last_modification", value: "$Date: 2016-12-30 13:54:28 +0100 (Fri, 30 Dec 2016) $" );
	script_tag( name: "creation_date", value: "2009-10-28 11:13:14 +0100 (Wed, 28 Oct 2009)" );
	script_bugtraq_id( 36821 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Asterisk Missing ACL Check Remote Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Ver", "Asterisk-PBX/Installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36821" );
	script_xref( name: "URL", value: "http://www.asterisk.org/" );
	script_xref( name: "URL", value: "http://downloads.digium.com/pub/security/AST-2009-007.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/507471" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Asterisk is prone to a security-bypass vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to make network calls that are
  supposed to be prohibited. This may lead to other attacks." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
if(version_in_range( version: version, test_version: "1.6.1", test_version2: "1.6.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
	security_message( port: port, data: report, protocol: proto );
	exit( 0 );
}
exit( 99 );

