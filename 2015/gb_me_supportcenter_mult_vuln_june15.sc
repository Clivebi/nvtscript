CPE = "cpe:/a:manageengine:supportcenter_plus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805807" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-5149", "CVE-2015-5150" );
	script_bugtraq_id( 75512, 75506 );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-06-25 12:35:38 +0530 (Thu, 25 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine SupportCenter Plus Multiple Vulnerabilities - June15" );
	script_tag( name: "summary", value: "The host is running ManageEngine
  SupportCenter Plus and prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Missing user access control mechanisms.

  - 'module' parameter to /workorder/Attachment.jsp?component=Request is not
    properly sanitized to check '../' characters.

  - 'query' and 'compAcct' parameters are not properly sanitized before passing
    to /jsp/ResetADPwd.jsp and jsp/CacheScreenWidth.jsp scripts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to inject HTML or script code, upload arbitrary files and bypass
  access restrictions." );
	script_tag( name: "affected", value: "ManageEngine SupportCenter Plus version 7.90" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/37322" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/535796/30/0/threaded" );
	script_xref( name: "URL", value: "http://www.vulnerability-lab.com/download_content.php?id=1501" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manageengine_supportcenter_detect.sc" );
	script_mandatory_keys( "ManageEngine/SupportCenter/Plus/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!appPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!appVer = get_app_version( cpe: CPE, port: appPort )){
	exit( 0 );
}
if(version_is_equal( version: appVer, test_version: "7900" )){
	report = "Installed version: " + appVer + "\n" + "Fixed version:     WillNotFix" + "\n";
	security_message( data: report, port: appPort );
	exit( 0 );
}

