CPE = "cpe:/a:microsoft:office_web_apps";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805992" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-6037" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-10-14 10:47:07 +0530 (Wed, 14 Oct 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Web Apps XSS Spoofing Vulnerability (3096440)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-110." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as the application fails to
  properly sanitize the malicious crafted request." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to perform cross-site scripting attacks on
  affected systems and run script in the security context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Office Web Apps 2010 Service Pack 2 and prior

  - Microsoft Office Web Apps Server 2013 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085571" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085520" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/ms15-110.aspx" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_office_web_apps_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Web/Apps/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
webappVer = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( webappVer, "^14\\..*" )){
	dllVer = fetch_file_version( sysPath: path, file_name: "\\14.0\\WebServices\\ConversionService\\Bin\\Converter\\sword.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7160.4999" )){
			report = "File checked:     " + path + "14.0\\WebServices\\ConversionService\\Bin\\Converter\\sword.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7160.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( webappVer, "^15\\..*" )){
	path = path + "\\PPTConversionService\\bin\\Converter\\";
	dllVer = fetch_file_version( sysPath: path, file_name: "msoserver.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4763.999" )){
			report = "File checked:     " + path + "msoserver.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4763.999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

