if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852421" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2018-1000877", "CVE-2018-1000878", "CVE-2018-1000879", "CVE-2018-1000880", "CVE-2019-1000019", "CVE-2019-1000020" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-04-13 02:01:02 +0000 (Sat, 13 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for libarchive (openSUSE-SU-2019:1196-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1196-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00055.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the openSUSE-SU-2019:1196-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libarchive fixes the following issues:

  Security issues fixed:

  - CVE-2018-1000877: Fixed a double free vulnerability in RAR decoder
  (bsc#1120653)

  - CVE-2018-1000878: Fixed a Use-After-Free vulnerability in RAR decoder
  (bsc#1120654)

  - CVE-2018-1000879: Fixed a NULL Pointer Dereference vulnerability in ACL
  parser (bsc#1120656)

  - CVE-2018-1000880: Fixed an Improper Input Validation vulnerability in
  WARC parser (bsc#1120659)

  - CVE-2019-1000019: Fixed an Out-Of-Bounds Read vulnerability in 7zip
  decompression (bsc#1124341)

  - CVE-2019-1000020: Fixed an Infinite Loop vulnerability in ISO9660 parser
  (bsc#1124342)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1196=1" );
	script_tag( name: "affected", value: "'libarchive' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "bsdtar", rpm: "bsdtar~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bsdtar-debuginfo", rpm: "bsdtar-debuginfo~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive-debugsource", rpm: "libarchive-debugsource~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive-devel", rpm: "libarchive-devel~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13", rpm: "libarchive13~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13-debuginfo", rpm: "libarchive13-debuginfo~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13-32bit", rpm: "libarchive13-32bit~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libarchive13-32bit-debuginfo", rpm: "libarchive13-32bit-debuginfo~3.3.2~lp150.7.1", rls: "openSUSELeap15.0" ) )){
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

