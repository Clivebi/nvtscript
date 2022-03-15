if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854102" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2021-36222" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-02 19:14:00 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-24 03:01:46 +0000 (Tue, 24 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for krb5 (openSUSE-SU-2021:1182-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1182-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5YD36VO3UYG3QGTYXP2IABP7W52ZZE6X" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the openSUSE-SU-2021:1182-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for krb5 fixes the following issues:

  - CVE-2021-36222: Fixed KDC null deref on bad encrypted challenge.
       (bsc#1188571)

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'krb5' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client", rpm: "krb5-client~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client-debuginfo", rpm: "krb5-client-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debugsource", rpm: "krb5-debugsource~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini", rpm: "krb5-mini~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-debuginfo", rpm: "krb5-mini-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-debugsource", rpm: "krb5-mini-debugsource~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-devel", rpm: "krb5-mini-devel~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-kdb-ldap", rpm: "krb5-plugin-kdb-ldap~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-kdb-ldap-debuginfo", rpm: "krb5-plugin-kdb-ldap-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-otp", rpm: "krb5-plugin-preauth-otp~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-otp-debuginfo", rpm: "krb5-plugin-preauth-otp-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-pkinit", rpm: "krb5-plugin-preauth-pkinit~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-pkinit-debuginfo", rpm: "krb5-plugin-preauth-pkinit-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server-debuginfo", rpm: "krb5-server-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit", rpm: "krb5-32bit~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit-debuginfo", rpm: "krb5-32bit-debuginfo~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel-32bit", rpm: "krb5-devel-32bit~1.16.3~lp152.5.19.1", rls: "openSUSELeap15.2" ) )){
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

