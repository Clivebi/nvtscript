CPE = "cpe:/a:novell:edirectory";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900210" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-02 16:25:07 +0200 (Tue, 02 Sep 2008)" );
	script_cve_id( "CVE-2008-5091", "CVE-2008-5092", "CVE-2008-5093", "CVE-2008-5094", "CVE-2008-5095" );
	script_bugtraq_id( 30947 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_name( "Novell eDirectory Multiple Vulnerabilities (Linux)" );
	script_dependencies( "secpod_novell_prdts_detect_lin.sc" );
	script_mandatory_keys( "Novell/eDir/Lin/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31684" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020788.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020787.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020786.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Aug/1020785.html" );
	script_xref( name: "URL", value: "http://download.novell.com/Download?buildid=RH_B5b3M6EQ~" );
	script_tag( name: "summary", value: "This host is running Novell eDirectory, which is prone to XSS,
  Denial of Service, and Remote Code Execution Vulnerabilities." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - errors in HTTP Protocol Stack that can be exploited to cause heap
  based buffer overflow via a specially crafted language/content-length headers.

  - input passed via unspecified parameters to the HTTP Protocol Stack is
  not properly sanitzed before being returned to the user.

  - Multiple unknown errors exist in LDAP and NDS services." );
	script_tag( name: "affected", value: "Novell eDirectory 8.8 SP2 and prior versions on Linux (All)." );
	script_tag( name: "solution", value: "Apply 8.8 Service Pack 3." );
	script_tag( name: "impact", value: "Successful Remote exploitation will allow execution of
  arbitrary code, heap-based buffer overflow, Cross Site Scripting attacks, or cause memory corruption." );
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
if(version_is_less( version: vers, test_version: "8.8.SP2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.8.SP3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

