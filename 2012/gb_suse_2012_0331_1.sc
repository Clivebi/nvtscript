if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850273" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 23:16:16 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2012-0768", "CVE-2012-0769" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "openSUSE-SU", value: "2012:0331-1" );
	script_name( "openSUSE: Security Advisory for flash-player (openSUSE-SU-2012:0331-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
	script_tag( name: "affected", value: "flash-player on openSUSE 11.4" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "flash-player 11.1.102.63 fixes two security issues:

  - memory corruption vulnerability in Matrix3D could lead to
  code executionn (CVE-2012-0768)

  - integer errors that could lead to information disclosure
  (CVE-2012-0769)" );
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
	if(!isnull( res = isrpmvuln( pkg: "flash-player", rpm: "flash-player~11.1.102.63~0.2.1", rls: "openSUSE11.4" ) )){
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

