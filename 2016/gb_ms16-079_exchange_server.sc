CPE = "cpe:/a:microsoft:exchange_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807839" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2015-6015", "CVE-2015-6014", "CVE-2015-6013" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-06-15 10:23:05 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Exchange Server Multiple Vulnerabilities (3160339)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-079." );
	script_tag( name: "vuldetect", value: "Gets the vulnerable file version and checks if the
  appropriate patch is applied or not." );
	script_tag( name: "insight", value: "Multiple flaws exist due to errors in Oracle
  Outside In libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to sensitive information and also get elevated privileges
  on the affected system." );
	script_tag( name: "affected", value: "- Microsoft Exchange Server 2007 Service Pack 3

  - Microsoft Exchange Server 2010 Service Pack 3

  - Microsoft Exchange Server 2013 Service Pack 1

  - Microsoft Exchange Server 2013 Cumulative Update 11

  - Microsoft Exchange Server 2013 Cumulative Update 12

  - Microsoft Exchange Server 2016

  - Microsoft Exchange Server 2016 Cumulative Update 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3160339" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-079" );
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
	if( version_in_range( version: exeVer, test_version: "8.0", test_version2: "8.3.467" ) ){
		Vulnerable_range = "8.0 - 8.3.467";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.3.300" ) ){
			Vulnerable_range = "14.0 - 14.3.300";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.847.46" )){
				Vulnerable_range = "15.0 - 15.0.847.46";
				VULN = TRUE;
			}
		}
	}
	if(IsMatchRegexp( exeVer, "^(15.0)" ) && ContainsString( cum_update, "Cumulative Update 11" )){
		if(version_is_less( version: exeVer, test_version: "15.0.1156.10" )){
			Vulnerable_range = "Less than 15.0.1156.10";
			VULN = TRUE;
		}
	}
	if( IsMatchRegexp( exeVer, "^(15.0)" ) && ContainsString( cum_update, "Cumulative Update 12" ) ){
		if(version_is_less( version: exeVer, test_version: "15.0.1178.6" )){
			Vulnerable_range = "Less than 15.0.1178.6";
			VULN = TRUE;
		}
	}
	else {
		if(version_in_range( version: exeVer, test_version: "15.1", test_version2: "15.1.225.48" )){
			Vulnerable_range = "15.1 - 15.1.225.48";
			VULN = TRUE;
		}
	}
	if(IsMatchRegexp( exeVer, "^(15.1)" ) && ContainsString( cum_update, "Cumulative Update 1" )){
		if(version_is_less( version: exeVer, test_version: "15.1.396.33" )){
			Vulnerable_range = "Less than 15.1.396.33";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + exchangePath + "\\Bin\\ExSetup.exe" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

