if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810282" );
	script_version( "2021-09-14T10:35:07+0000" );
	script_cve_id( "CVE-2016-7142" );
	script_bugtraq_id( 92737 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 10:35:07 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-14 12:33:00 +0000 (Mon, 14 Sep 2020)" );
	script_tag( name: "creation_date", value: "2017-01-16 14:56:16 +0530 (Mon, 16 Jan 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "InspIRCd < 2.0.23 'm_sasl' Module SASL_EXTERNAL Authentication Spoofing Vulnerability" );
	script_tag( name: "summary", value: "InspIRCd is prone to an authentication spoofing vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the 'm_sasl' module in InspIRC,
  when used with a service that supports SASL_EXTERNAL authentication" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to spoof
  certificate fingerprints via crafted SASL messages to the IRCd. This allows any user to login as
  any other user that they know the certificate fingerprint of, and that user has services
  configured to accept SASL EXTERNAL login requests for." );
	script_tag( name: "affected", value: "InspIRCd versions before 2.0.23." );
	script_tag( name: "solution", value: "Update to version 2.0.23 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.inspircd.org/2016/09/03/v2023-released.html" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/09/05/8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ircd.sc" );
	script_require_ports( "Services/irc", 6667 );
	script_mandatory_keys( "ircd/banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 6667, proto: "irc" );
if(!banner = get_kb_item( "irc/banner/" + port )){
	exit( 0 );
}
if(!ContainsString( banner, "InspIRCd" )){
	exit( 0 );
}
vers = eregmatch( pattern: "InspIRCd-([0-9.]+)", string: banner );
if(!vers[1]){
	exit( 0 );
}
if(version_is_less( version: vers[1], test_version: "2.0.23" )){
	report = report_fixed_ver( installed_version: vers[1], fixed_version: "2.0.23" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

