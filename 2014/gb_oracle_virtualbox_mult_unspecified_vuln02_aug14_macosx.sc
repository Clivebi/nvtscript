if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804694" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-2477", "CVE-2014-2486", "CVE-2014-2488", "CVE-2014-2489" );
	script_bugtraq_id( 68613, 68618, 68621, 68610 );
	script_tag( name: "cvss_base", value: "4.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-08-04 11:30:13 +0530 (Mon, 04 Aug 2014)" );
	script_name( "Oracle VM VirtualBox Multiple Unspecified Vulnerabilities-02 Aug2014 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM VirtualBox and is prone to multiple
  unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to unspecified errors related to the 'core'
  subcomponent." );
	script_tag( name: "impact", value: "Successful exploitation will allow local users to affect confidentiality,
  integrity, and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle VM VirtualBox before versions 3.2.24, 4.0.26, 4.1.34, 4.2.26, and
  4.3.12." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59510" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_oracle_virtualbox_detect_macosx.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:oracle:vm_virtualbox",
	 "cpe:/a:sun:virtualbox" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^[34]\\." )){
	if(version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.23" ) || version_in_range( version: vers, test_version: "4.0.0", test_version2: "4.0.25" ) || version_in_range( version: vers, test_version: "4.1.0", test_version2: "4.1.33" ) || version_in_range( version: vers, test_version: "4.2.0", test_version2: "4.2.25" ) || version_in_range( version: vers, test_version: "4.3.0", test_version2: "4.3.11" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

