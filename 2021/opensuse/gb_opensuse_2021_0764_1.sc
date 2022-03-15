if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853822" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2021-3516", "CVE-2021-3517", "CVE-2021-3518", "CVE-2021-3537" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 11:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-24 03:00:59 +0000 (Mon, 24 May 2021)" );
	script_name( "openSUSE: Security Advisory for libxml2 (openSUSE-SU-2021:0764-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0764-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/32MGTWHTQRUPYHYIAVT6OVBDWQDI36DX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2'
  package(s) announced via the openSUSE-SU-2021:0764-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libxml2 fixes the following issues:

  - CVE-2021-3537: NULL pointer dereference in
       valid.c:xmlValidBuildAContentModel (bsc#1185698)

  - CVE-2021-3518: Fixed a use after free in xinclude.c:xmlXIncludeDoProcess
       (bsc#1185408).

  - CVE-2021-3517: Fixed a heap based buffer overflow in
       entities.c:xmlEncodeEntitiesInternal (bsc#1185410).

  - CVE-2021-3516: Fixed a use after free in
       entities.c:xmlEncodeEntitiesInternal (bsc#1185409).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'libxml2' package(s) on openSUSE Leap 15.2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2", rpm: "libxml2-2~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-debuginfo", rpm: "libxml2-2-debuginfo~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-debugsource", rpm: "libxml2-debugsource~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools", rpm: "libxml2-tools~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools-debuginfo", rpm: "libxml2-tools-debuginfo~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2-python-debugsource", rpm: "python-libxml2-python-debugsource~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-libxml2-python", rpm: "python2-libxml2-python~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-libxml2-python-debuginfo", rpm: "python2-libxml2-python-debuginfo~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-libxml2-python", rpm: "python3-libxml2-python~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-libxml2-python-debuginfo", rpm: "python3-libxml2-python-debuginfo~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-32bit", rpm: "libxml2-2-32bit~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-32bit-debuginfo", rpm: "libxml2-2-32bit-debuginfo~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-devel-32bit", rpm: "libxml2-devel-32bit~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-doc", rpm: "libxml2-doc~2.9.7~lp152.10.12.1", rls: "openSUSELeap15.2" ) )){
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

