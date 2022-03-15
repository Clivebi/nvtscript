CPE = "cpe:/a:avast:antivirus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810203" );
	script_version( "2019-10-29T06:41:59+0000" );
	script_cve_id( "CVE-2016-4025" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-10-29 06:41:59 +0000 (Tue, 29 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-11-18 14:57:52 +0530 (Fri, 18 Nov 2016)" );
	script_name( "Avast Free Antivirus Sandbox Escape Security Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Avast Free
  Antivirus and is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a design flaw in the
  Avast DeepScreen feature." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to escape from a fully sandboxed process, furthermore attacker can also freely
  modify or infect or encrypt any existing file in the case of a ransomware attack." );
	script_tag( name: "affected", value: "Avast Free Antivirus 11.x through 11.1.2262." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://labs.nettitude.com/blog/escaping-avast-sandbox-using-single-ioctl-cve-2016-4025" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_avast_av_detect_win.sc" );
	script_mandatory_keys( "avast/antivirus_free/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(IsMatchRegexp( version, "^11" ) && version_in_range( version: version, test_version: "11.0", test_version2: "11.1.2262" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "WillNotFix", install_path: location );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

