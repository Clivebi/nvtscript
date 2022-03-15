CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100366" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-12-01 12:01:39 +0100 (Tue, 01 Dec 2009)" );
	script_bugtraq_id( 37153 );
	script_cve_id( "CVE-2009-4055" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Asterisk RTP Comfort Noise Processing Remote Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Ver", "Asterisk-PBX/Installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37153" );
	script_xref( name: "URL", value: "http://www.asterisk.org/" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2009-010.html" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Asterisk is prone to a remote denial-of-service vulnerability because
  it fails to properly handle malformed RTP comfort noise data." );
	script_tag( name: "impact", value: "Successful exploits can crash the application, resulting in denial-of-
  service conditions for legitimate users." );
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
if(version_in_range( version: version, test_version: "1.6.1", test_version2: "1.6.1.10" ) || version_in_range( version: version, test_version: "1.4.27", test_version2: "1.4.27.0" ) || version_in_range( version: version, test_version: "1.2", test_version2: "1.2.36" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
	security_message( port: port, data: report, protocol: proto );
	exit( 0 );
}
exit( 99 );

