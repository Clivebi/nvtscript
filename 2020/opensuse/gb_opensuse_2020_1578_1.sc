if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853470" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-8927" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-02 12:15:00 +0000 (Wed, 02 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-09-30 03:04:51 +0000 (Wed, 30 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for brotli (openSUSE-SU-2020:1578-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1578-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00108.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'brotli'
  package(s) announced via the openSUSE-SU-2020:1578-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for brotli fixes the following issues:

  brotli was updated to 1.0.9:

  * CVE-2020-8927: Fix integer overflow when input chunk is longer than 2GiB
  [boo#1175825]

  * `brotli -v` now reports raw / compressed size

  * decoder: minor speed / memory usage improvements

  * encoder: fix rare access to uninitialized data in ring-buffer


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1578=1" );
	script_tag( name: "affected", value: "'brotli' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "brotli", rpm: "brotli~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "brotli-debuginfo", rpm: "brotli-debuginfo~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "brotli-debugsource", rpm: "brotli-debugsource~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotli-devel", rpm: "libbrotli-devel~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlicommon1", rpm: "libbrotlicommon1~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlicommon1-debuginfo", rpm: "libbrotlicommon1-debuginfo~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlidec1", rpm: "libbrotlidec1~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlidec1-debuginfo", rpm: "libbrotlidec1-debuginfo~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlienc1", rpm: "libbrotlienc1~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlienc1-debuginfo", rpm: "libbrotlienc1-debuginfo~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlicommon1-32bit", rpm: "libbrotlicommon1-32bit~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlicommon1-32bit-debuginfo", rpm: "libbrotlicommon1-32bit-debuginfo~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlidec1-32bit", rpm: "libbrotlidec1-32bit~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlidec1-32bit-debuginfo", rpm: "libbrotlidec1-32bit-debuginfo~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlienc1-32bit", rpm: "libbrotlienc1-32bit~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbrotlienc1-32bit-debuginfo", rpm: "libbrotlienc1-32bit-debuginfo~1.0.9~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

