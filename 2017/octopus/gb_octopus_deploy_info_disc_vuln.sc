CPE = "cpe:/a:octopus:octopus_deploy";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140522" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-21 14:49:47 +0700 (Tue, 21 Nov 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-15609" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Octopus Deploy Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_octopus_deploy_detect.sc" );
	script_mandatory_keys( "octopus/octopus_deploy/detected" );
	script_tag( name: "summary", value: "Octopus allows attackers to obtain sensitive cleartext information by
reading a variable JSON file in certain situations involving Offline Drop Targets." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Octopus Deploy version 3.2.5 until 3.17.6." );
	script_tag( name: "solution", value: "Update to version 3.17.7 or later." );
	script_xref( name: "URL", value: "https://github.com/OctopusDeploy/Issues/issues/3868" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.2.5", test_version2: "3.17.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.17.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

