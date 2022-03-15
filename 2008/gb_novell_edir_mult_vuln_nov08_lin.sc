CPE = "cpe:/a:novell:edirectory";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800136" );
	script_version( "$Revision: 12741 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-10 13:18:00 +0100 (Mon, 10 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5091", "CVE-2008-5092", "CVE-2008-5093", "CVE-2008-5094" );
	script_bugtraq_id( 30947 );
	script_name( "Novell eDirectory Multiple Vulnerabilities Nov08 - (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_novell_prdts_detect_lin.sc" );
	script_mandatory_keys( "Novell/eDir/Lin/Ver" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020785.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020786.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020787.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020788.html" );
	script_xref( name: "URL", value: "http://www.novell.com/support/viewContent.do?externalId=3426981" );
	script_xref( name: "URL", value: "http://www.novell.com/documentation/edir873/sp10_readme/netware/readme.txt" );
	script_xref( name: "URL", value: "http://support.novell.com/patches.html" );
	script_tag( name: "impact", value: "Successful exploitation allows remote code execution on the target
  machines or can allow disclosure of potentially sensitive information or
  can cause denial of service condition." );
	script_tag( name: "affected", value: "Novell eDirectory 8.8 SP2 and prior on Linux." );
	script_tag( name: "insight", value: "The flaws are due to

  - boundary error in LDAP and NDS services.

  - boundary error in HTTP language header and HTTP content-length header.

  - HTTP protocol stack(HTTPSTK) that does not properly filter HTML code from
  user-supplied input." );
	script_tag( name: "solution", value: "Update to 8.8 Service Pack 3." );
	script_tag( name: "summary", value: "This host is running Novell eDirectory and is prone to Multiple
  Vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "8.8.SP3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.8.SP3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

