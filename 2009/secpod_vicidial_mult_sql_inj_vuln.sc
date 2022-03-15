CPE = "cpe:/a:vicidial:vicidial";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900916" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2234" );
	script_bugtraq_id( 35056 );
	script_name( "VICIdial Multiple SQLi Vulnerabilities (CVE-2009-2234)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8755" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50665" );
	script_xref( name: "URL", value: "http://www.eflo.net/VICIDIALforum/viewtopic.php?t=8075" );
	script_xref( name: "URL", value: "http://www.eflo.net/vicidial/security_fix_admin_20090522.patch" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_vicidial_detect.sc" );
	script_mandatory_keys( "vicidial/detected" );
	script_tag( name: "summary", value: "VICIdial is prone to multiple SQL injection (SQLi) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This flaw occurs due to lack of sanitation of user supplied data
  passed into the admin.php and can be exploited via username and password parameters." );
	script_tag( name: "impact", value: "Attackers can exploit this issue via specially crafted SQL
  statements to access and modify the back-end database." );
	script_tag( name: "affected", value: "VICIdial 2.0.5 through 2.0.5-173." );
	script_tag( name: "solution", value: "Apply the available patch linked at the references." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
version = ereg_replace( pattern: "-", replace: ".", string: version );
if(version_is_less_equal( version: version, test_version: "2.0.5.206" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply patch" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

