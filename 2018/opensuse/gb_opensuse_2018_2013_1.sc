if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851817" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-20 05:54:39 +0200 (Fri, 20 Jul 2018)" );
	script_cve_id( "CVE-2017-1000422" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-02 16:35:00 +0000 (Thu, 02 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for gdk-pixbuf (openSUSE-SU-2018:2013-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdk-pixbuf'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gdk-pixbuf fixes the following security issue:

  - CVE-2017-1000422: Prevent several integer overflow in the gif_get_lzw
  function resulting in memory corruption and potential code execution
  (bsc#1074462).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-741=1" );
	script_tag( name: "affected", value: "gdk-pixbuf on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2013-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-07/msg00025.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-debugsource", rpm: "gdk-pixbuf-debugsource~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-devel", rpm: "gdk-pixbuf-devel~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-devel-debuginfo", rpm: "gdk-pixbuf-devel-debuginfo~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders", rpm: "gdk-pixbuf-query-loaders~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-debuginfo", rpm: "gdk-pixbuf-query-loaders-debuginfo~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0", rpm: "libgdk_pixbuf-2_0-0~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-debuginfo", rpm: "libgdk_pixbuf-2_0-0-debuginfo~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GdkPixbuf-2_0", rpm: "typelib-1_0-GdkPixbuf-2_0~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-lang", rpm: "gdk-pixbuf-lang~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-devel-32bit", rpm: "gdk-pixbuf-devel-32bit~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-devel-debuginfo-32bit", rpm: "gdk-pixbuf-devel-debuginfo-32bit~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-32bit", rpm: "gdk-pixbuf-query-loaders-32bit~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdk-pixbuf-query-loaders-debuginfo-32bit", rpm: "gdk-pixbuf-query-loaders-debuginfo-32bit~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-32bit", rpm: "libgdk_pixbuf-2_0-0-32bit~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgdk_pixbuf-2_0-0-debuginfo-32bit", rpm: "libgdk_pixbuf-2_0-0-debuginfo-32bit~2.34.0~16.1", rls: "openSUSELeap42.3" ) )){
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

