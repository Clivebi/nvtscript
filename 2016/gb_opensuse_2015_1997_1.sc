if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851195" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-02-02 17:17:52 +0100 (Tue, 02 Feb 2016)" );
	script_cve_id( "CVE-2015-2695", "CVE-2015-2696", "CVE-2015-2697" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for krb5 (openSUSE-SU-2015:1997-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "krb5 was updated to fix three security issues.

  These security issues were fixed:

  - CVE-2015-2695: Applications which call gss_inquire_context() on a
  partially-established SPNEGO context could have caused the GSS-API
  library to read from a pointer using the wrong type, generally causing a
  process crash. (bsc#952188).

  - CVE-2015-2696: Applications which call gss_inquire_context() on a
  partially-established IAKERB context could have caused the GSS-API
  library to read from a pointer using the wrong type, generally causing a
  process crash. (bsc#952189).

  - CVE-2015-2697: Incorrect string handling in build_principal_va can lead
  to DOS (bsc#952190)." );
	script_tag( name: "affected", value: "krb5 on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:1997-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client", rpm: "krb5-client~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-client-debuginfo", rpm: "krb5-client-debuginfo~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debugsource", rpm: "krb5-debugsource~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-doc", rpm: "krb5-doc~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini", rpm: "krb5-mini~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-debuginfo", rpm: "krb5-mini-debuginfo~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-debugsource", rpm: "krb5-mini-debugsource~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-mini-devel", rpm: "krb5-mini-devel~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-kdb-ldap", rpm: "krb5-plugin-kdb-ldap~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-kdb-ldap-debuginfo", rpm: "krb5-plugin-kdb-ldap-debuginfo~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-otp", rpm: "krb5-plugin-preauth-otp~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-otp-debuginfo", rpm: "krb5-plugin-preauth-otp-debuginfo~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-pkinit", rpm: "krb5-plugin-preauth-pkinit~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-plugin-preauth-pkinit-debuginfo", rpm: "krb5-plugin-preauth-pkinit-debuginfo~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server-debuginfo", rpm: "krb5-server-debuginfo~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-32bit", rpm: "krb5-32bit~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debuginfo-32bit", rpm: "krb5-debuginfo-32bit~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel-32bit", rpm: "krb5-devel-32bit~1.12.1~21.1", rls: "openSUSELeap42.1" ) )){
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

