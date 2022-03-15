if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852792" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-17540", "CVE-2018-5388" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-18 14:28:00 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-12-01 03:01:13 +0000 (Sun, 01 Dec 2019)" );
	script_name( "openSUSE: Security Advisory for strongswan (openSUSE-SU-2019:2594-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2594-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00077.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'strongswan'
  package(s) announced via the openSUSE-SU-2019:2594-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for strongswan fixes the following issues:

  Security issues fixed:

  - CVE-2018-5388: Fixed a buffer underflow which may allow to a remote
  attacker with local user credentials to resource exhaustion and denial
  of service while reading from the socket (bsc#1094462).

  - CVE-2018-10811: Fixed a denial of service during  the IKEv2 key
  derivation if the openssl plugin is used in FIPS mode and HMAC-MD5 is
  negotiated as PRF (bsc#1093536).

  - CVE-2018-16151, CVE-2018-16152: Fixed multiple flaws in the gmp plugin
  which might lead to authorization bypass (bsc#1107874).

  - CVE-2018-17540: Fixed an improper input validation in gmp plugin
  (bsc#1109845).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2594=1" );
	script_tag( name: "affected", value: "'strongswan' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "strongswan-doc", rpm: "strongswan-doc~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan", rpm: "strongswan~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-debuginfo", rpm: "strongswan-debuginfo~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-debugsource", rpm: "strongswan-debugsource~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-hmac", rpm: "strongswan-hmac~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-ipsec", rpm: "strongswan-ipsec~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-ipsec-debuginfo", rpm: "strongswan-ipsec-debuginfo~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-libs0", rpm: "strongswan-libs0~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-libs0-debuginfo", rpm: "strongswan-libs0-debuginfo~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-mysql", rpm: "strongswan-mysql~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-mysql-debuginfo", rpm: "strongswan-mysql-debuginfo~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-nm", rpm: "strongswan-nm~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-nm-debuginfo", rpm: "strongswan-nm-debuginfo~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-sqlite", rpm: "strongswan-sqlite~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-sqlite-debuginfo", rpm: "strongswan-sqlite-debuginfo~5.6.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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

