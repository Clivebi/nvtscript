CPE = "cpe:/a:xymon:xymon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902504" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)" );
	script_cve_id( "CVE-2011-1716" );
	script_bugtraq_id( 47156 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Xymon Monitor Unspecified Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44036" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66542" );
	script_xref( name: "URL", value: "http://xymon.svn.sourceforge.net/viewvc/xymon/branches/4.3.2/Changes?revision=6673&view=markup" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xymon_monitor_detect.sc" );
	script_mandatory_keys( "xymon/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Xymon Monitor versions 4.3.0 and prior." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input by
  multiple unspecified scripts which allows attackers to execute arbitrary
  HTML and script code on the web server." );
	script_tag( name: "solution", value: "Upgrade to Xymon Monitor version 4.3.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Xymon Monitor and is prone to unspecified
  multiple cross site scripting vulnerabilities." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "4.3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

