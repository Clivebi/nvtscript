CPE = "cpe:/a:microsoft:exchange_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809314" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-0138" );
	script_bugtraq_id( 92806 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-09-14 10:21:52 +0530 (Wed, 14 Sep 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Exchange Server Information Disclosure Vulnerabilities (3185883)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-108." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the way that Microsoft
  Exchange Server parses email messages." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  an attacker to discover confidential user information that is contained in
  Microsoft Outlook applications." );
	script_tag( name: "affected", value: "- Microsoft Exchange Server 2007 Service Pack 3

  - Microsoft Exchange Server 2010 Service Pack 3

  - Microsoft Exchange Server 2013 Service Pack 1

  - Microsoft Exchange Server 2013 Cumulative Update 12

  - Microsoft Exchange Server 2013 Cumulative Update 13

  - Microsoft Exchange Server 2016 Cumulative Update 1

  - Microsoft Exchange Server 2016 Cumulative Update 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3184736" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-108" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_exchange_server_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Exchange/Server/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
exchangePath = get_app_location( cpe: CPE, skip_port: TRUE );
if(!exchangePath || ContainsString( exchangePath, "Could not find the install location" )){
	exit( 0 );
}
cum_update = get_kb_item( "MS/Exchange/Cumulative/Update/no" );
exeVer = fetch_file_version( sysPath: exchangePath, file_name: "Bin\\ExSetup.exe" );
if(exeVer){
	if( version_in_range( version: exeVer, test_version: "8.0", test_version2: "8.3.485.0" ) ){
		Vulnerable_range = "8.0 - 8.3.485.0";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.3.319.1" )){
			Vulnerable_range = "14.0 - 14.3.319.2";
			VULN = TRUE;
		}
	}
	if( version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.847.49" ) ){
		Vulnerable_range = "15.0 - 15.0.847.50";
		VULN = TRUE;
	}
	else {
		if( IsMatchRegexp( exeVer, "^(15.0)" ) && ContainsString( cum_update, "Cumulative Update 13" ) ){
			if(version_is_less( version: exeVer, test_version: "15.0.1210.6" )){
				Vulnerable_range = "Less than 15.0.1210.6";
				VULN = TRUE;
			}
		}
		else {
			if( IsMatchRegexp( exeVer, "^(15.0)" ) && ContainsString( cum_update, "Cumulative Update 12" ) ){
				if(version_is_less( version: exeVer, test_version: "15.0.1178.9" )){
					Vulnerable_range = "Less than 15.0.1178.9";
					VULN = TRUE;
				}
			}
			else {
				if( IsMatchRegexp( exeVer, "^(15.1)" ) && ContainsString( cum_update, "Cumulative Update 1" ) ){
					if(version_is_less( version: exeVer, test_version: "15.1.396.37" )){
						Vulnerable_range = "Less than 15.1.396.37";
						VULN = TRUE;
					}
				}
				else {
					if(IsMatchRegexp( exeVer, "^(15.1)" ) && ContainsString( cum_update, "Cumulative Update 2" )){
						if(version_is_less( version: exeVer, test_version: "15.1.466.37" )){
							Vulnerable_range = "Less than 15.1.466.37";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + exchangePath + "\\Bin\\ExSetup.exe" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

