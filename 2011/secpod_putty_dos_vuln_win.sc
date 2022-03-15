CPE = "cpe:/a:putty:putty";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902780" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-26 18:52:49 +0530 (Mon, 26 Dec 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "PuTTY DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_putty_portable_detect.sc" );
	script_mandatory_keys( "putty/detected" );
	script_tag( name: "summary", value: "PuTTY is prone to denial of service (DoS) vulnerability." );
	script_tag( name: "insight", value: "The flaw is caused to unspecified error in the application." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a DoS." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PuTTY version 0.60" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18270/" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/108151/Putty-0.60-Denial-Of-Service.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "0.60" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

