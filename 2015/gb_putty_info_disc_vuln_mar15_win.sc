CPE = "cpe:/a:putty:putty";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805434" );
	script_version( "2021-06-01T06:37:42+0000" );
	script_tag( name: "last_modification", value: "2021-06-01 06:37:42 +0000 (Tue, 01 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-03-31 13:05:20 +0530 (Tue, 31 Mar 2015)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2015-2157" );
	script_bugtraq_id( 72825 );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PuTTY Information Disclosure vulnerability Mar15 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_putty_portable_detect.sc" );
	script_mandatory_keys( "putty/detected" );
	script_tag( name: "summary", value: "PuTTY is prone to information disclosure vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to the program failing to
  clear SSH-2 private key information from the memory during the saving or
  loading of key files to disk." );
	script_tag( name: "impact", value: "Successful exploitation will allow a local attacker
  to gain access to potentially sensitive information." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PuTTY version 0.51 through 0.63 on Windows." );
	script_tag( name: "solution", value: "Update to version 0.64 or later." );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/02/28/4" );
	script_xref( name: "URL", value: "http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped-2.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_in_range( version: version, test_version: "0.51", test_version2: "0.63" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.64", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

