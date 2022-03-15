if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852273" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2018-5729", "CVE-2018-5730" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-21 15:47:00 +0000 (Tue, 21 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-02-06 04:05:31 +0100 (Wed, 06 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for krb5 (openSUSE-SU-2019:0139-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0139-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00006.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the openSUSE-SU-2019:0139-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for krb5 fixes the following issues:

  Security issues fixed:

  - CVE-2018-5729, CVE-2018-5730: Fixed multiple flaws in LDAP DN checking
  (bsc#1083926, bsc#1083927)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-139=1" );
	script_tag( name: "affected", value: "krb5 on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client", rpm: "krb5-client~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client-debuginfo", rpm: "krb5-client-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debugsource", rpm: "krb5-debugsource~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini", rpm: "krb5-mini~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-debuginfo", rpm: "krb5-mini-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-debugsource", rpm: "krb5-mini-debugsource~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-devel", rpm: "krb5-mini-devel~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-kdb-ldap", rpm: "krb5-plugin-kdb-ldap~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-kdb-ldap-debuginfo", rpm: "krb5-plugin-kdb-ldap-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-otp", rpm: "krb5-plugin-preauth-otp~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-otp-debuginfo", rpm: "krb5-plugin-preauth-otp-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-pkinit", rpm: "krb5-plugin-preauth-pkinit~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-pkinit-debuginfo", rpm: "krb5-plugin-preauth-pkinit-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server-debuginfo", rpm: "krb5-server-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit", rpm: "krb5-32bit~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit-debuginfo", rpm: "krb5-32bit-debuginfo~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel-32bit", rpm: "krb5-devel-32bit~1.15.2~lp150.5.6.1", rls: "openSUSELeap15.0" ) )){
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

