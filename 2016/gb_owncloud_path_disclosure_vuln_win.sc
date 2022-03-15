CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807444" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-1501" );
	script_bugtraq_id( 80382 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-01-12 02:48:00 +0000 (Tue, 12 Jan 2016)" );
	script_tag( name: "creation_date", value: "2016-03-02 15:04:46 +0530 (Wed, 02 Mar 2016)" );
	script_name( "ownCloud Path Disclosure Vulnerability Feb16 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with ownCloud and
  is prone to path disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an owncloud return
  exception error messages." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  authenticated adversary to gain information about the installation path of
  the ownCloud instance." );
	script_tag( name: "affected", value: "ownCloud Server 8.x before 8.0.9 and 8.1.x
  before 8.1.4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to ownCloud Server 8.0.9 or 8.1.4
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2016-004" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "owncloud/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ownPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ownVer = get_app_version( cpe: CPE, port: ownPort )){
	exit( 0 );
}
if(IsMatchRegexp( ownVer, "^8" )){
	if( version_in_range( version: ownVer, test_version: "8.0.0", test_version2: "8.0.8" ) ){
		fix = "8.0.9";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: ownVer, test_version: "8.1.0", test_version2: "8.1.3" )){
			fix = "8.1.4";
			VULN = TRUE;
		}
	}
}

