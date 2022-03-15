if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853516" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-24659" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-26 16:15:00 +0000 (Mon, 26 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-25 04:00:47 +0000 (Sun, 25 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for gnutls (openSUSE-SU-2020:1724-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1724-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00054.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
  package(s) announced via the openSUSE-SU-2020:1724-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gnutls fixes the following issues:

  - Fix heap buffer overflow in handshake with no_renegotiation alert sent
  (CVE-2020-24659 bsc#1176181)

  - FIPS: Implement (EC)DH requirements from SP800-56Arev3 (bsc#1176086)

  - FIPS: Use 2048 bit prime in DH selftest (bsc#1176086)

  - FIPS: Add TLS KDF selftest (bsc#1176671)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1724=1" );
	script_tag( name: "affected", value: "'gnutls' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-debuginfo", rpm: "gnutls-debuginfo~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-debugsource", rpm: "gnutls-debugsource~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-guile", rpm: "gnutls-guile~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-guile-debuginfo", rpm: "gnutls-guile-debuginfo~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-dane-devel", rpm: "libgnutls-dane-devel~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-dane0", rpm: "libgnutls-dane0~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-dane0-debuginfo", rpm: "libgnutls-dane0-debuginfo~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-devel", rpm: "libgnutls-devel~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls30", rpm: "libgnutls30~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls30-debuginfo", rpm: "libgnutls30-debuginfo~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls30-hmac", rpm: "libgnutls30-hmac~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutlsxx-devel", rpm: "libgnutlsxx-devel~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutlsxx28", rpm: "libgnutlsxx28~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutlsxx28-debuginfo", rpm: "libgnutlsxx28-debuginfo~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-devel-32bit", rpm: "libgnutls-devel-32bit~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls30-32bit", rpm: "libgnutls30-32bit~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls30-32bit-debuginfo", rpm: "libgnutls30-32bit-debuginfo~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls30-hmac-32bit", rpm: "libgnutls30-hmac-32bit~3.6.7~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
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

