if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851743" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-12 05:51:31 +0200 (Sat, 12 May 2018)" );
	script_cve_id( "CVE-2016-1516", "CVE-2016-1517" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-20 13:23:00 +0000 (Wed, 20 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for opencv (openSUSE-SU-2018:1265-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opencv'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for opencv fixes the following issues:

  - CVE-2016-1517: Fixed a denial of service (segfault) via vectors
  involving corrupt chunks (boo#1033150)

  - CVE-2016-1516: Fixed a double free issue that allows attackers to
  execute arbitrary code (boo#1033152).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-455=1" );
	script_tag( name: "affected", value: "opencv on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1265-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-05/msg00067.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "libopencv-qt56_3", rpm: "libopencv-qt56_3~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopencv-qt56_3-debuginfo", rpm: "libopencv-qt56_3-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopencv3_1", rpm: "libopencv3_1~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopencv3_1-debuginfo", rpm: "libopencv3_1-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv", rpm: "opencv~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-debuginfo", rpm: "opencv-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-debugsource", rpm: "opencv-debugsource~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-devel", rpm: "opencv-devel~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-doc", rpm: "opencv-doc~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-qt5", rpm: "opencv-qt5~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-qt5-debuginfo", rpm: "opencv-qt5-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-qt5-debugsource", rpm: "opencv-qt5-debugsource~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-qt5-devel", rpm: "opencv-qt5-devel~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opencv-qt5-doc", rpm: "opencv-qt5-doc~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-opencv", rpm: "python-opencv~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-opencv-debuginfo", rpm: "python-opencv-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-opencv-qt5", rpm: "python-opencv-qt5~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-opencv-qt5-debuginfo", rpm: "python-opencv-qt5-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-opencv", rpm: "python3-opencv~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-opencv-debuginfo", rpm: "python3-opencv-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-opencv-qt5", rpm: "python3-opencv-qt5~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-opencv-qt5-debuginfo", rpm: "python3-opencv-qt5-debuginfo~3.1.0~4.3.1", rls: "openSUSELeap42.3" ) )){
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

