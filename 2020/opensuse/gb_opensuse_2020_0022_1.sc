if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852981" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2019-13627" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-01 13:25:00 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-01-14 04:01:19 +0000 (Tue, 14 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for libgcrypt (openSUSE-SU-2020:0022-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0022-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00018.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgcrypt'
  package(s) announced via the openSUSE-SU-2020:0022-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libgcrypt fixes the following issues:

  Security issues fixed:

  - CVE-2019-13627: Mitigation against an ECDSA timing attack (bsc#1148987).

  Bug fixes:

  - Added CMAC AES self test (bsc#1155339).

  - Added CMAC TDES self test missing (bsc#1155338).

  - Fix test dsa-rfc6979 in FIPS mode.

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-22=1" );
	script_tag( name: "affected", value: "'libgcrypt' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-cavs", rpm: "libgcrypt-cavs~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-cavs-debuginfo", rpm: "libgcrypt-cavs-debuginfo~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-debugsource", rpm: "libgcrypt-debugsource~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel", rpm: "libgcrypt-devel~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel-debuginfo", rpm: "libgcrypt-devel-debuginfo~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20", rpm: "libgcrypt20~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-debuginfo", rpm: "libgcrypt20-debuginfo~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-hmac", rpm: "libgcrypt20-hmac~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel-32bit", rpm: "libgcrypt-devel-32bit~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel-32bit-debuginfo", rpm: "libgcrypt-devel-32bit-debuginfo~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-32bit", rpm: "libgcrypt20-32bit~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-32bit-debuginfo", rpm: "libgcrypt20-32bit-debuginfo~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-hmac-32bit", rpm: "libgcrypt20-hmac-32bit~1.8.2~lp151.9.7.1", rls: "openSUSELeap15.1" ) )){
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

