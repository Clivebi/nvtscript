CPE = "cpe:/a:sympa:sympa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100299" );
	script_version( "2020-02-25T07:14:55+0000" );
	script_tag( name: "last_modification", value: "2020-02-25 07:14:55 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "creation_date", value: "2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)" );
	script_bugtraq_id( 30727 );
	script_cve_id( "CVE-2008-4476" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Sympa 'sympa.pl' Insecure Temporary File Creation Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/30727" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=494969" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "sympa_detect.sc" );
	script_mandatory_keys( "sympa/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Sympa creates temporary files in an insecure manner." );
	script_tag( name: "impact", value: "An attacker with local access could potentially exploit this issue to
  perform symbolic-link attacks, overwriting arbitrary files in the context of the affected application.

  Successfully mounting a symlink attack may allow the attacker to delete or corrupt sensitive files, which may
  result in a denial of service. Other attacks may also be possible." );
	script_tag( name: "affected", value: "Sympa 5.4.3 is vulnerable, other versions may also be affected." );
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
if(version_is_less_equal( version: version, test_version: "5.4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

