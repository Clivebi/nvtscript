CPE = "cpe:/a:horde:horde_groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108115" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2017-7413", "CVE-2017-7414" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-05 09:33:23 +0200 (Wed, 05 Apr 2017)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Horde Webmail Remote Code Execution Vulnerability in Horde_Crypt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "horde_detect.sc" );
	script_mandatory_keys( "horde/installed" );
	script_xref( name: "URL", value: "https://lists.horde.org/archives/horde/Week-of-Mon-20170403/056767.html" );
	script_xref( name: "URL", value: "https://lists.horde.org/archives/horde/Week-of-Mon-20170403/056768.html" );
	script_tag( name: "summary", value: "The Horde_Crypt library used in Horde Webmail is prone to a remote code
  execution vulnerability if the PGP feature is enabled." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker may execute shell commands in the context of an admin or user." );
	script_tag( name: "affected", value: "Horde_Crypt library prior to 2.7.6 as used in Horde Webmail 5.2.18 and prior." );
	script_tag( name: "solution", value: "Update Horde Webmail to version 5.2.19 or later which includes a fixed version 2.7.6 of Horde_Crypt." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "5.2.19" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.19" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

