CPE = "cpe:/a:microsoft:silverlight";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809323" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-3367" );
	script_bugtraq_id( 92837 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-09-21 16:02:13 +0530 (Wed, 21 Sep 2016)" );
	script_name( "Microsoft Silverlight Remote Code Execution Vulnerability (3182373) (MAC OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-109." );
	script_tag( name: "vuldetect", value: "Gets the vulnerable file version and
  checks if the appropriate patch is applied or not." );
	script_tag( name: "insight", value: "The flaw exists due when Microsoft
  Silverlight improperly allows applications to access objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation could corrupt system
  memory, which could allow an attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Silverlight version 5 on MAC OS X." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3182373" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-109" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_ms_silverlight_detect_macosx.sc" );
	script_mandatory_keys( "MS/Silverlight/MacOSX/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!msl_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( msl_ver, "^5\\." )){
	if(version_is_less( version: msl_ver, test_version: "5.1.50709.0" )){
		report = " Silverlight version:     " + msl_ver + "\n" + "Vulnerable range:  5.0 - 5.1.50709.0" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

