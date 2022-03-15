CPE = "cpe:/a:microsoft:silverlight";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804407" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-0319" );
	script_bugtraq_id( 66046 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-03-12 08:02:21 +0530 (Wed, 12 Mar 2014)" );
	script_name( "Microsoft Silverlight DEP/ASLR Security Bypass Vulnerability (2932677)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-014." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is caused when Silverlight improperly handles certain objects in
  memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information." );
	script_tag( name: "affected", value: "Microsoft Silverlight version 5." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2932677" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-014" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(version_in_range( version: msl_ver, test_version: "5.0", test_version2: "5.1.30213" )){
		report = "Silverlight version:  " + msl_ver + "\n" + "Vulnerable range:  5.0 - 5.1.30213" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

