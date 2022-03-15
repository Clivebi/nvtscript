if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113124" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-06 12:23:32 +0100 (Tue, 06 Mar 2018)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-29 14:40:00 +0000 (Thu, 29 Mar 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-7567" );
	script_name( "OTRS 5.0.24 and 6.0.1 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a Remote Code Execution vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "In the Admin Package Manager in Open Ticket Request System (OTRS),
  authenticated admins are able to exploit a Blind Remote Code Execution vulnerability by loading a crafted
  opm file with an embedded CodeInstall element to execute a command on the server during package installation." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to gain complete control
  over the target system." );
	script_tag( name: "affected", value: "OTRS 5.0.0 through 5.0.24 and 6.0.0 through 6.0.1." );
	script_tag( name: "solution", value: "Update to ORTS 5.0.25 or 6.0.2 respectively." );
	script_xref( name: "URL", value: "https://0day.today/exploit/29938" );
	exit( 0 );
}
CPE = "cpe:/a:otrs:otrs";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.25" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.2" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

