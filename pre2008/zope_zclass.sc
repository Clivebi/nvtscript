if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10777" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0567" );
	script_name( "Zope ZClass Permission Mapping Bug" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Alert4Web.com" );
	script_family( "Web Servers" );
	script_dependencies( "gb_zope_detect.sc" );
	script_mandatory_keys( "zope/detected" );
	script_tag( name: "solution", value: "Upgrade to Zope 2.3.3 or apply the hotfix referenced in the vendor
  advisory above." );
	script_tag( name: "summary", value: "The remote web server uses a version of Zope which is older than
  version 2.3.3. In such versions, any user can visit a ZClass declaration and change the ZClass
  permission mappings for methods and other objects defined within the ZClass, possibly allowing for
  unauthorized access within the Zope instance." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
CPE = "cpe:/a:zope:zope";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.3", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

