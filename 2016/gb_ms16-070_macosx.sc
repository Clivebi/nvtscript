CPE = "cpe:/a:microsoft:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807846" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0025" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-06-16 09:43:02 +0530 (Thu, 16 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Remote Code Execution Vulnerability-3163610(Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-070" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in Microsoft Office
  software when the Office software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers  to execute arbitrary code in the context of the currently
  logged-in user." );
	script_tag( name: "affected", value: "Microsoft Office 2011 on Mac OS X." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3165796" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-070" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
offVer = get_kb_item( "MS/Office/MacOSX/Ver" );
if(!offVer){
	exit( 0 );
}
officePath = get_app_location( cpe: CPE, skip_port: TRUE );
if(!officePath || ContainsString( officePath, "Could not find the install location" )){
	exit( 0 );
}
if(version_in_range( version: offVer, test_version: "14.1.0", test_version2: "14.6.4" )){
	report = "File checked:      " + officePath + "\n" + "File version:      " + offVer + "\n" + "Vulnerable range: 14.1.0 - 14.6.4 " + "\n";
	security_message( data: report );
}

