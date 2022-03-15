if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851601" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-30 07:23:21 +0200 (Wed, 30 Aug 2017)" );
	script_cve_id( "CVE-2016-1531", "CVE-2016-9963", "CVE-2017-1000369" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for exim (openSUSE-SU-2017:2289-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for exim fixes the following issues:

  Changes in exim:

  - specify users with ref:mail, to make them dynamic. (boo#1046971)

  - CVE-2017-1000369: Fixed memory leaks that could be exploited to 'stack
  crash' local privilege escalation (boo#1044692)

  - Require user(mail) group(mail) to meet new users handling in TW.

  - Prerequire permissions (fixes rpmlint).

  - conditionally disable DANE on SuSE versions with OpenSSL   1.0

  - CVE-2016-1531: when installed setuid root, allows local users to gain
  privileges via the perl_startup argument.

  - CVE-2016-9963: DKIM information leakage (boo#1015930)


  - Makefile tuning:
  + add sqlite support
  + disable WITH_OLD_DEMIME
  + enable AUTH_CYRUS_SASL
  + enable AUTH_TLS
  + enable SYSLOG_LONG_LINES
  + enable SUPPORT_PAM
  + MAX_NAMED_LIST=64
  + enable EXPERIMENTAL_DMARC
  + enable EXPERIMENTAL_EVENT
  + enable EXPERIMENTAL_PROXY
  + enable EXPERIMENTAL_CERTNAMES
  + enable EXPERIMENTAL_DSN
  + enable EXPERIMENTAL_DANE
  + enable EXPERIMENTAL_SOCKS
  + enable EXPERIMENTAL_INTERNATIONAL" );
	script_tag( name: "affected", value: "exim on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2289-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "exim", rpm: "exim~4.86.2~10.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exim-debuginfo", rpm: "exim-debuginfo~4.86.2~10.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exim-debugsource", rpm: "exim-debugsource~4.86.2~10.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon", rpm: "eximon~4.86.2~10.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon-debuginfo", rpm: "eximon-debuginfo~4.86.2~10.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximstats-html", rpm: "eximstats-html~4.86.2~10.6.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "exim", rpm: "exim~4.86.2~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exim-debuginfo", rpm: "exim-debuginfo~4.86.2~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exim-debugsource", rpm: "exim-debugsource~4.86.2~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon", rpm: "eximon~4.86.2~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon-debuginfo", rpm: "eximon-debuginfo~4.86.2~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximstats-html", rpm: "eximstats-html~4.86.2~14.1", rls: "openSUSELeap42.3" ) )){
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

