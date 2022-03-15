CPE = "cpe:/a:microsoft:exchange_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811227" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_cve_id( "CVE-2017-8621", "CVE-2017-8559", "CVE-2017-8560" );
	script_bugtraq_id( 99533, 99448, 99449 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-17 18:48:00 +0000 (Mon, 17 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-07-12 10:07:15 +0530 (Wed, 12 Jul 2017)" );
	script_name( "Microsoft Exchange Server Multiple Vulnerabilities (KB4018588)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4018588" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Microsoft Exchange that could lead to spoofing.

  - An error when Microsoft Exchange Outlook Web Access (OWA) fails to properly
    handle web requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to perform script/content injection attacks and attempt to trick the user into
  disclosing sensitive information." );
	script_tag( name: "affected", value: "- Microsoft Exchange Server 2013 Cumulative Update 16

  - Microsoft Exchange Server 2010 Service Pack 3

  - Microsoft Exchange Server 2016 Cumulative Update 5" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4018588" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_exchange_server_detect.sc" );
	script_mandatory_keys( "MS/Exchange/Server/Ver" );
	script_require_ports( 139, 445 );
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
	if( version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.1293.3" ) ){
		Vulnerable_range = "15.0 - 15.0.1293.3";
		VULN = TRUE;
	}
	else {
		if( IsMatchRegexp( exeVer, "^(15.0)" ) && ContainsString( cum_update, "Cumulative Update 16" ) ){
			if(version_is_less( version: exeVer, test_version: "15.1.845.36" )){
				Vulnerable_range = "Less than 15.1.845.36";
				VULN = TRUE;
			}
		}
		else {
			if(IsMatchRegexp( exeVer, "^(15\\.)" ) && ContainsString( cum_update, "Cumulative Update 5" )){
				if(version_is_less( version: exeVer, test_version: "15.0.847.55" )){
					Vulnerable_range = "Less than 15.0.847.55";
					VULN = TRUE;
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

