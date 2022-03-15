CPE = "cpe:/a:microsoft:silverlight";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806013" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-2435", "CVE-2015-2455", "CVE-2015-2456", "CVE-2015-2463", "CVE-2015-2464" );
	script_bugtraq_id( 76238, 76216, 76241, 76239, 76240 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-08-13 11:13:34 +0530 (Thu, 13 Aug 2015)" );
	script_name( "Microsoft Silverlight Remote Code Execution Vulnerability (3078662)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-080." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper memory
  operations performed by the affected software while handling content with
  crafted TrueType fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code in the context of the vulnerable application. Failed
  exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Microsoft Silverlight version 5." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3080333" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-080" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_silverlight_detect.sc" );
	script_mandatory_keys( "Microsoft/Silverlight/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!msl_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( msl_ver, "^5\\." )){
	if(version_in_range( version: msl_ver, test_version: "5.0", test_version2: "5.1.40727" )){
		report = "Silverlight version:  " + msl_ver + "\n" + "Vulnerable range:  5.0 - 5.1.40727" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

