CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801332" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)" );
	script_cve_id( "CVE-2010-1728" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Apple Safari 'webkit' Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/393589.php" );
	script_xref( name: "URL", value: "https://launchpad.net/bugs/cve/2010-1729" );
	script_xref( name: "URL", value: "http://security-tracker.debian.org/tracker/CVE-2010-1729" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to crash the
  affected browser, resulting in a denial of service condition." );
	script_tag( name: "affected", value: "Apple Safari version (Safari.exe) 4.531.9.1." );
	script_tag( name: "insight", value: "The flaw exists due to error in 'WebKit.dll' file in webkit
  when processing 'JavaScript' that writes sequences in an infinite loop." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Apple Safari Web Browser and is
  prone to Denial of Service vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
func find_version( filepath ){
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: filepath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: filepath );
	dllVer = GetVer( file: file, share: share );
	return dllVer;
}
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
path = infos["location"];
key = "SOFTWARE\\Apple Computer, Inc.\\Safari";
asFile = registry_get_sz( item: "BrowserExe", key: key );
if(asFile){
	exeVer = find_version( filepath: asFile );
	if(!isnull( exeVer )){
		if(version_is_less_equal( version: exeVer, test_version: "4.31.9.1" )){
			file = asFile - "\\Safari\\Safari.exe\\Common Files\\Apple\\Apple Application Support\\WebKit.dll";
			dllVer = find_version( filepath: file );
			if(!isnull( dllVer )){
				if(version_is_less_equal( version: dllVer, test_version: "4.31.9.1" )){
					report = report_fixed_ver( installed_version: dllVer, fixed_version: "None", install_path: path, file_checked: file );
					security_message( port: 0, data: report );
					exit( 0 );
				}
				exit( 99 );
			}
		}
	}
}
exit( 0 );

