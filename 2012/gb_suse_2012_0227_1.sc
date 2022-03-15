if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850266" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 23:08:35 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2011-4028", "CVE-2011-4029" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "openSUSE-SU", value: "2012:0227-1" );
	script_name( "openSUSE: Security Advisory for xorg-x11-server (openSUSE-SU-2012:0227-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.3" );
	script_tag( name: "affected", value: "xorg-x11-server on openSUSE 11.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "The X server had two security issues and one bug that is
  fixed by this update.

  CVE-2011-4028: It is possible for a local attacker to
  deduce if a file exists or not by exploiting the way that
  Xorg creates its lock files.

  CVE-2011-4029: It is possible for a non-root local user to
  set the read permission for all users on any file or
  directory." );
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
if(release == "openSUSE11.3"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~7.5_1.8.0~10.15.2", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~7.5_1.8.0~10.15.2", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra", rpm: "xorg-x11-server-extra~7.5_1.8.0~10.15.2", rls: "openSUSE11.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-sdk", rpm: "xorg-x11-server-sdk~7.5_1.8.0~10.15.2", rls: "openSUSE11.3" ) )){
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

