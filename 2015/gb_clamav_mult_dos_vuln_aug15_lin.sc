CPE = "cpe:/a:clamav:clamav";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806019" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-2668", "CVE-2015-2222", "CVE-2015-2221", "CVE-2015-2170" );
	script_bugtraq_id( 74472, 74443 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-08-17 12:16:12 +0530 (Mon, 17 Aug 2015)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ClamAV Multiple Denial of Service Vulnerabilities August15 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with ClamAV and is
  prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - an error that is triggered when handling a specially crafted xz archive file,
  which can cause an infinite loops.

  - an error in the 'cli_scanpe' function in pe.c script that is triggered when
  handling petite packed files.

  - an error in the 'yc_poly_emulator' function in yc.c script that is
  triggered when handling a specially crafted y0da cryptor file.

  - an error in the 'pefromupx' function of the UPX decoder that is
  triggered when handling specially crafted files." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to crash the application." );
	script_tag( name: "affected", value: "ClamAV versions before 0.98.7 on Linux" );
	script_tag( name: "solution", value: "Upgrade to ClamAV version 0.98.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://blog.clamav.net/2015/04/clamav-0987-has-been-released.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_remote_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "ClamAV/remote/Ver", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 3310 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!clamPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!clamVer = get_app_version( cpe: CPE, port: clamPort )){
	exit( 0 );
}
if(version_is_less( version: clamVer, test_version: "0.98.7" )){
	report = "Installed Version: " + clamVer + "\n" + "Fixed Version:     " + "0.98.7" + "\n";
	security_message( data: report, port: clamPort );
	exit( 0 );
}

