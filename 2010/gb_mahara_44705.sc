CPE = "cpe:/a:mahara:mahara";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100897" );
	script_version( "2020-03-12T04:31:01+0000" );
	script_tag( name: "last_modification", value: "2020-03-12 04:31:01 +0000 (Thu, 12 Mar 2020)" );
	script_tag( name: "creation_date", value: "2010-11-09 13:58:26 +0100 (Tue, 09 Nov 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 44705 );
	script_cve_id( "CVE-2010-3871" );
	script_name( "Mahara 'groupviews.tpl' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44705" );
	script_xref( name: "URL", value: "http://wiki.mahara.org/Release_Notes/1.3.3" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_mahara_detect.sc" );
	script_mandatory_keys( "mahara/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for details." );
	script_tag( name: "summary", value: "Mahara is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary HTML and
  script code in the browser of an unsuspecting user in the context of
  the affected site. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to Mahara 1.3.3 are vulnerable." );
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
if(version_is_less( version: version, test_version: "1.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

