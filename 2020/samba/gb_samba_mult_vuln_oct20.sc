CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117046" );
	script_version( "2020-11-17T10:22:06+0000" );
	script_tag( name: "last_modification", value: "2020-11-17 10:22:06 +0000 (Tue, 17 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-17 09:55:31 +0000 (Tue, 17 Nov 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2000-0935", "CVE-2000-0936", "CVE-2000-0937", "CVE-2000-0938", "CVE-2000-0939" );
	script_bugtraq_id( 1872, 1873, 1874 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Samba <= 2.0.7 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "The Samba Web Administration Tool (SWAT) shipped in Samba
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Samba versions 2.0.7 and prior." );
	script_tag( name: "solution", value: "Update to version 2.0.8 or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/1872" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/1873" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/1874" );
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
if(version_is_less_equal( version: version, test_version: "2.0.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

