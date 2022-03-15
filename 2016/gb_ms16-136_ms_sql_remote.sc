if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809096" );
	script_version( "2021-04-08T12:57:28+0000" );
	script_cve_id( "CVE-2016-7249", "CVE-2016-7250", "CVE-2016-7251", "CVE-2016-7252", "CVE-2016-7253", "CVE-2016-7254" );
	script_bugtraq_id( 94037, 94060, 94043, 94050, 94061, 94056 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-08 12:57:28 +0000 (Thu, 08 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-11-14 15:30:37 +0530 (Mon, 14 Nov 2016)" );
	script_name( "Microsoft SQL Server Multiple Vulnerabilities (3199641)" );
	script_tag( name: "summary", value: "This host is missing an important
  security update according to Microsoft Bulletin MS16-136." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The Microsoft SQL Server improperly handles pointer casting.

  - The SQL Server MDS does not properly validate a request parameter on the SQL
    Server site.

  - An improper check of 'FILESTREAM' path.

  - The SQL Server Agent incorrectly check ACLs on atxcore.dll." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain elevated privileges that could be used to view, change,
  or delete data, or create new accounts, also can gain additional database and
  file information and to spoof content, disclose information, or take any action
  that the user could take on the site on behalf of the targeted user." );
	script_tag( name: "affected", value: "- Microsoft SQL Server 2012 x86/x64 Edition Service Pack 2 and prior

  - Microsoft SQL Server 2012 x86/x64 Edition Service Pack 3 and prior

  - Microsoft SQL Server 2014 x86/x64 Edition Service Pack 1 and prior

  - Microsoft SQL Server 2014 x86/x64 Edition Service Pack 2 and prior

  - Microsoft SQL Server 2016 x64 Edition" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-136" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "mssqlserver_detect.sc" );
	script_mandatory_keys( "MS/SQLSERVER/Running" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:microsoft:sql_server_2012:sp2",
	 "cpe:/a:microsoft:sql_server_2012:sp3",
	 "cpe:/a:microsoft:sql_server_2014:sp1",
	 "cpe:/a:microsoft:sql_server_2014:sp2",
	 "cpe:/a:microsoft:sql_server_2016" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!vers = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if( IsMatchRegexp( vers, "^11\\.0" ) ){
	if( version_in_range( version: vers, test_version: "11.0.5400.0", test_version2: "11.0.5675.0" ) ){
		VULN = TRUE;
		vulnerable_range = "11.0.5400.0 - 11.0.5675.0";
	}
	else {
		if(version_in_range( version: vers, test_version: "11.0.5058.0", test_version2: "11.0.5387.0" )){
			VULN = TRUE;
			vulnerable_range = "11.0.5000.0 - 11.0.5387.0";
		}
	}
}
else {
	if( IsMatchRegexp( vers, "^11\\.0" ) ){
		if( version_in_range( version: vers, test_version: "11.0.6000.0", test_version2: "11.0.6247.0" ) ){
			VULN = TRUE;
			vulnerable_range = "11.0.6000.0 - 11.0.6247.0";
		}
		else {
			if(version_in_range( version: vers, test_version: "11.0.6400.0", test_version2: "11.0.6566.0" )){
				VULN = TRUE;
				vulnerable_range = "11.0.6400.0 - 11.0.6566.0";
			}
		}
	}
	else {
		if( IsMatchRegexp( vers, "^12\\.0" ) ){
			if( version_in_range( version: vers, test_version: "12.0.4000.0", test_version2: "12.0.4231.0" ) ){
				VULN = TRUE;
				vulnerable_range = "12.0.4000.0 - 12.0.4231.0";
			}
			else {
				if(version_in_range( version: vers, test_version: "12.0.4300.0", test_version2: "12.0.4486.0" )){
					VULN = TRUE;
					vulnerable_range = "12.0.4300.0 - 12.0.4486.0";
				}
			}
		}
		else {
			if( IsMatchRegexp( vers, "^12\\.0" ) ){
				if( version_in_range( version: vers, test_version: "12.0.5000.0", test_version2: "12.0.5202.0" ) ){
					VULN = TRUE;
					vulnerable_range = "12.0.5000.0 - 12.0.5202.0";
				}
				else {
					if(version_in_range( version: vers, test_version: "12.0.5400.0", test_version2: "12.0.5531.0" )){
						VULN = TRUE;
						vulnerable_range = "12.0.5400.0 - 12.0.5531.0";
					}
				}
			}
			else {
				if(IsMatchRegexp( vers, "^13\\.0" )){
					if( version_in_range( version: vers, test_version: "13.0.1000.0", test_version2: "13.0.1721.0" ) ){
						VULN = TRUE;
						vulnerable_range = "13.0.1000.0 - 13.0.1721.0";
					}
					else {
						if(version_in_range( version: vers, test_version: "13.0.2000.0", test_version2: "13.0.2185.2" )){
							VULN = TRUE;
							vulnerable_range = "13.0.2000.0 - 13.0.2185.2";
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "Vulnerable range: " + vulnerable_range + "\n";
	security_message( data: report, port: port );
	exit( 0 );
}

