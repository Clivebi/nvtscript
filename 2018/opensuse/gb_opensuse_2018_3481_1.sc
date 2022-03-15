if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852097" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2018-16554", "CVE-2018-17088", "CVE-2016-3822" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-31 20:15:00 +0000 (Tue, 31 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-10-27 06:24:34 +0200 (Sat, 27 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for jhead (openSUSE-SU-2018:3481-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2018:3481-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00074.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jhead'
  package(s) announced via the openSUSE-SU-2018:3481-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for jhead fixes the following issues:

  Security issues fixed:

  - CVE-2018-17088: The ProcessGpsInfo function may have allowed a remote
  attacker to cause a denial-of-service attack or unspecified other impact
  via a malicious JPEG file, because there is an integer overflow during a
  check for whether a location exceeds the EXIF data length. This is
  analogous to the CVE-2016-3822 integer overflow in exif.c.  (boo#1108672)

  - CVE-2018-16554: The ProcessGpsInfo function may have allowed a remote
  attacker to cause a denial-of-service attack or unspecified other impact
  via a malicious JPEG file, because of inconsistency between float and
  double in a sprintf format string during TAG_GPS_ALT handling.
  (boo#1108480)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1292=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1292=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1292=1" );
	script_tag( name: "affected", value: "jhead on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "jhead", rpm: "jhead~3.00~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jhead-debuginfo", rpm: "jhead-debuginfo~3.00~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jhead-debugsource", rpm: "jhead-debugsource~3.00~14.1", rls: "openSUSELeap42.3" ) )){
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "jhead", rpm: "jhead~3.00~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jhead-debuginfo", rpm: "jhead-debuginfo~3.00~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jhead-debugsource", rpm: "jhead-debugsource~3.00~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
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

