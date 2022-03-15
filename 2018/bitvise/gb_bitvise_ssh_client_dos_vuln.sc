CPE = "cpe:/a:bitvise:ssh_client";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813386" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-06-04 13:54:02 +0530 (Mon, 04 Jun 2018)" );
	script_name( "Bitvise SSH Client Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Bitvise SSH
  Client Suite and is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an invalid memory access
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to cause the target client to stop processing." );
	script_tag( name: "affected", value: "Bitvise SSH Client 6.xx and 7.xx
  before 7.41." );
	script_tag( name: "solution", value: "Upgrade to version 7.41 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.bitvise.com/flowssh-version-history#security-notification-741" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_bitvise_ssh_client_detect.sc" );
	script_mandatory_keys( "BitviseSSH/Client/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^(6|7)\\." ) && version_is_less( version: vers, test_version: "7.41.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.41", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

