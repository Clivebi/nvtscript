CPE = "cpe:/a:kamailio:kamailio";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105592" );
	script_cve_id( "CVE-2016-2385" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12096 $" );
	script_name( "Kamailio SEAS module encode_msg heap buffer overflow" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-03-31 14:51:12 +0200 (Thu, 31 Mar 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_kamailio_detect.sc" );
	script_mandatory_keys( "kamailio/version" );
	script_xref( name: "URL", value: "https://census-labs.com/news/2016/03/30/kamailio-seas-heap-overflow/" );
	script_tag( name: "impact", value: "An attacker may exploit this issue to cause a denial-of-service condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The heap overflow can be triggered if Kamailio is configured to use the SEAS module" );
	script_tag( name: "solution", value: "Update to Kamailio 4.3.5 or newer" );
	script_tag( name: "summary", value: "According to its self reported version, the remote Kamailio server is prone to a heap buffer overflow." );
	script_tag( name: "affected", value: "Kamailio version below 4.3.5 with an enabled SEAS module" );
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
if(version_is_less( version: version, test_version: "4.3.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.5" );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

