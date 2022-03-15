CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150739" );
	script_version( "2021-10-06T05:01:59+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-09-24 10:59:30 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-1999-0810", "CVE-1999-0812" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Samba < 2.0.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "Samba is prone to multiple Vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "All Samba versions of nmbd prior to 2.0.5 are vulnerable to a
denial of service attack causing nmbd to either crash or to go into an infinite loop. No known
instances of this attack being exploited have been reported." );
	script_tag( name: "affected", value: "Samba versions prior to 2.0.5." );
	script_tag( name: "solution", value: "Update to version 2.0.5 or later." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/history/samba-2.0.5.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

