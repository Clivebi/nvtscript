CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900812" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2651" );
	script_bugtraq_id( 35837 );
	script_name( "Asterisk RTP Text Frames Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Ver", "Asterisk-PBX/Installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36039/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2067" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2009-004.html" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2009-004-1.6.1.diff.txt" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause Denial of Service
  in the victim's system." );
	script_tag( name: "affected", value: "Asterisk version 1.6.1 and before 1.6.1.2 on Linux." );
	script_tag( name: "insight", value: "Error in main/rtp.c file which can be exploited via an RTP text frame without
  a certain delimiter that triggers a NULL pointer dereference and the subsequent calculation to an invalid pointer." );
	script_tag( name: "summary", value: "This host has Asterisk installed and is prone to Denial of Service
  vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Asterisk version 1.6.1.2 or later." );
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
if(version_in_range( version: version, test_version: "1.6.1", test_version2: "1.6.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.1.2" );
	security_message( port: port, data: report, protocol: proto );
	exit( 0 );
}
exit( 99 );

