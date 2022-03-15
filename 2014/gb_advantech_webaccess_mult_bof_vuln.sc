CPE = "cpe:/a:advantech:advantech_webaccess";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804478" );
	script_version( "2019-04-06T12:52:40+0000" );
	script_cve_id( "CVE-2014-0985", "CVE-2014-0986", "CVE-2014-0987", "CVE-2014-0988", "CVE-2014-0989", "CVE-2014-0990", "CVE-2014-0991", "CVE-2014-0992" );
	script_bugtraq_id( 69529, 69531, 69532, 69533, 69534, 69535, 69536, 69538 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-04-06 12:52:40 +0000 (Sat, 06 Apr 2019)" );
	script_tag( name: "creation_date", value: "2014-09-08 12:07:35 +0530 (Mon, 08 Sep 2014)" );
	script_name( "Advantech WebAccess Multiple Stack Based Buffer Overflow Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Advantech WebAccess
  and is prone to multiple stack based buffer overflow vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The multiple stack based buffer
  overflow flaws are due to an error when parsing NodeName, GotoCmd,
  NodeName2, AccessCode, AccessCode2, UserName, projectname, password
  parameters" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers execution of arbitrary code within the context of the
  application, or otherwise crash the whole application." );
	script_tag( name: "affected", value: "Advantech WebAccess before 7.3" );
	script_tag( name: "solution", value: "Upgrade to Advantech
  WebAccess 7.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/advisories/advantech-webaccess-vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_advantech_webaccess_consolidation.sc" );
	script_mandatory_keys( "advantech/webaccess/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port )){
	exit( 0 );
}
path = infos["location"];
vers = infos["version"];
if(version_is_less( version: vers, test_version: "7.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.3", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

