if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850180" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 20:17:46 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2011-4315" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:0237-1" );
	script_name( "openSUSE: Security Advisory for nginx (openSUSE-SU-2012:0237-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nginx'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
	script_tag( name: "affected", value: "nginx on openSUSE 11.4" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "A flaw in the custom DNS resolver of nginx could lead to a
  heap based buffer overflow which could potentially allow
  attackers to execute arbitrary code or to cause a Denial of
  Service (bnc#731084, CVE-2011-4315).
  Special Instructions and Notes:

  Please reboot the system after installing this update." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "nginx-0.8", rpm: "nginx-0.8~0.8.53~4.9.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

