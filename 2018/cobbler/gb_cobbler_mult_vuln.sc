if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112358" );
	script_version( "2021-09-29T11:43:49+0000" );
	script_cve_id( "CVE-2018-1000225", "CVE-2018-1000226" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 11:43:49 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-08-21 09:48:12 +0200 (Tue, 21 Aug 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cobbler <= 2.6.11+ Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "Cobbler is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws consist of a persistent XSS vulnerability and an incorrect authentication vulnerability." );
	script_tag( name: "affected", value: "Cobbler versions up to and including 2.6.11." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://movermeyer.com/2018-08-02-privilege-escalation-exploits-in-cobblers-api/" );
	script_xref( name: "URL", value: "https://github.com/cobbler/cobbler/issues/1916" );
	script_xref( name: "URL", value: "https://github.com/cobbler/cobbler/issues/1917" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_cobbler_detect.sc" );
	script_mandatory_keys( "Cobbler/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:michael_dehaan:cobbler";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.6.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

