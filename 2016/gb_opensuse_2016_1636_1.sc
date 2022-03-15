if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851347" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-21 05:48:07 +0200 (Tue, 21 Jun 2016)" );
	script_cve_id( "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-16 13:15:00 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for ntp (openSUSE-SU-2016:1636-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ntp was updated to version 4.2.8p8 to fix five security issues.

  These security issues were fixed:

  - CVE-2016-4953: Bad authentication demobilizes ephemeral associations
  (bsc#982065).

  - CVE-2016-4954: Processing spoofed server packets (bsc#982066).

  - CVE-2016-4955: Autokey association reset (bsc#982067).

  - CVE-2016-4956: Broadcast interleave (bsc#982068).

  - CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).

  These non-security issues were fixed:

  - Keep the parent process alive until the daemon has finished
  initialisation, to make sure that the PID file exists when the parent
  returns.

  - bsc#979302: Change the process name of the forking DNS worker process to
  avoid the impression that ntpd is started twice.

  - bsc#981422: Don't ignore SIGCHILD because it breaks wait().

  - bsc#979981: ntp-wait does not accept fractional seconds, so use 1
  instead of 0.2 in ntp-wait.service.

  - Separate the creation of ntp.keys and key #1 in it to avoid problems
  when upgrading installations that have the file, but no key #1, which is
  needed e.g. by 'rcntp addserver'.

  This update was imported from the SUSE:SLE-12-SP1:Update update project." );
	script_tag( name: "affected", value: "ntp on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1636-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.8p8~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debuginfo", rpm: "ntp-debuginfo~4.2.8p8~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debugsource", rpm: "ntp-debugsource~4.2.8p8~24.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.8p8~24.1", rls: "openSUSELeap42.1" ) )){
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

