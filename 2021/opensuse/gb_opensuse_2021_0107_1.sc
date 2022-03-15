if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853584" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-25709", "CVE-2020-25710" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:55:27 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for openldap2 (openSUSE-SU-2021:0107-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0107-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DU5LAY3LI5VYENQTLYA5AGNA47GQHI2B" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openldap2'
  package(s) announced via the openSUSE-SU-2021:0107-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openldap2 fixes the following issues:

     Security issues fixed:

  - CVE-2020-25709: Fixed a crash caused by specially crafted network
       traffic (bsc#1178909).

  - CVE-2020-25710: Fixed a crash caused by specially crafted network
       traffic (bsc#1178909).

     Non-security issue fixed:

  - Retry binds in the LDAP backend when the remote LDAP server disconnected
       the (idle) LDAP connection. (bsc#1179503)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'openldap2' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2", rpm: "libldap-2_4-2~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-debuginfo", rpm: "libldap-2_4-2-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2", rpm: "openldap2~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-meta", rpm: "openldap2-back-meta~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-meta-debuginfo", rpm: "openldap2-back-meta-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-perl", rpm: "openldap2-back-perl~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-perl-debuginfo", rpm: "openldap2-back-perl-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-sock", rpm: "openldap2-back-sock~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-sock-debuginfo", rpm: "openldap2-back-sock-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-sql", rpm: "openldap2-back-sql~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-sql-debuginfo", rpm: "openldap2-back-sql-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client", rpm: "openldap2-client~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client-debuginfo", rpm: "openldap2-client-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-contrib", rpm: "openldap2-contrib~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-contrib-debuginfo", rpm: "openldap2-contrib-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-debuginfo", rpm: "openldap2-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-debugsource", rpm: "openldap2-debugsource~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-devel", rpm: "openldap2-devel~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-devel-static", rpm: "openldap2-devel-static~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-ppolicy-check-password", rpm: "openldap2-ppolicy-check-password~1.2~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-ppolicy-check-password-debuginfo", rpm: "openldap2-ppolicy-check-password-debuginfo~1.2~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-data", rpm: "libldap-data~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-doc", rpm: "openldap2-doc~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-32bit", rpm: "libldap-2_4-2-32bit~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-32bit-debuginfo", rpm: "libldap-2_4-2-32bit-debuginfo~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-devel-32bit", rpm: "openldap2-devel-32bit~2.4.46~lp152.14.15.1", rls: "openSUSELeap15.2" ) )){
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

