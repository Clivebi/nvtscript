CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802235" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)" );
	script_cve_id( "CVE-2010-1824", "CVE-2010-4008", "CVE-2010-4494", "CVE-2011-0111", "CVE-2011-0112", "CVE-2011-0113", "CVE-2011-0114", "CVE-2011-0115", "CVE-2011-0116", "CVE-2011-0117", "CVE-2011-0118", "CVE-2011-0119", "CVE-2011-0120", "CVE-2011-0121", "CVE-2011-0122", "CVE-2011-0123", "CVE-2011-0124", "CVE-2011-0125", "CVE-2011-0126", "CVE-2011-0127", "CVE-2011-0128", "CVE-2011-0129", "CVE-2011-0130", "CVE-2011-0131", "CVE-2011-0132", "CVE-2011-0133", "CVE-2011-0134", "CVE-2011-0135", "CVE-2011-0136", "CVE-2011-0137", "CVE-2011-0138", "CVE-2011-0139", "CVE-2011-0140", "CVE-2011-0141", "CVE-2011-0142", "CVE-2011-0143", "CVE-2011-0144", "CVE-2011-0145", "CVE-2011-0146", "CVE-2011-0147", "CVE-2011-0148", "CVE-2011-0149", "CVE-2011-0150", "CVE-2011-0151", "CVE-2011-0152", "CVE-2011-0153", "CVE-2011-0154", "CVE-2011-0155", "CVE-2011-0156", "CVE-2011-0160", "CVE-2011-0161", "CVE-2011-0163", "CVE-2011-0165", "CVE-2011-0166", "CVE-2011-0167", "CVE-2011-0168", "CVE-2011-0169" );
	script_bugtraq_id( 44779, 46677, 46684, 46686, 46687, 46688, 46689, 46690, 46691, 46692, 46693, 46694, 46695, 46696, 46698, 46699, 46700, 46701, 46702, 46704, 46705, 46706, 46707, 46708, 46709, 46710, 46711, 46712, 46713, 46714, 46715, 46716, 46717, 46718, 46719, 46720, 46721, 46722, 46723, 46724, 46725, 46726, 46727, 46728, 46744, 46745, 46746, 46747, 46748, 46749, 46808, 46809, 46811, 46814, 46816 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Apple Safari Multiple Vulnerabilities - March 2011 (Mac OS X)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4566" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43696" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2011/mar/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to disclose potentially
  sensitive information, conduct cross-site scripting and spoofing attacks, and compromise a user's system." );
	script_tag( name: "affected", value: "Apple Safari versions prior to 5.0.4." );
	script_tag( name: "insight", value: "Please see the references for more details about the vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 5.0.4 or later." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.0.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.0.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

