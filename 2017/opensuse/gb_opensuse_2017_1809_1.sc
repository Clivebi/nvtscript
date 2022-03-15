if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851576" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-14 15:54:56 +0530 (Fri, 14 Jul 2017)" );
	script_cve_id( "CVE-2017-3142", "CVE-2017-3143" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-30 17:15:00 +0000 (Fri, 30 Aug 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for bind (openSUSE-SU-2017:1809-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bind fixes the following issues:

  - An attacker with the ability to send and receive messages to an
  authoritative DNS server was able to circumvent TSIG authentication of
  AXFR requests. A server that relied solely on TSIG keys for protection
  could be manipulated into (1) providing an AXFR of a zone to an
  unauthorized recipient and (2) accepting bogus Notify packets.
  [bsc#1046554, CVE-2017-3142]

  - An attacker who with the ability to send and receive messages to an
  authoritative DNS server and who had knowledge of a valid TSIG key name
  for the zone and service being targeted was able to manipulate BIND into
  accepting an unauthorized dynamic update. [bsc#1046555, CVE-2017-3143]

  This update was imported from the SUSE:SLE-12-SP1:Update update project." );
	script_tag( name: "affected", value: "bind on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:1809-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo", rpm: "bind-libs-debuginfo~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd", rpm: "bind-lwresd~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd-debuginfo", rpm: "bind-lwresd-debuginfo~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-32bit", rpm: "bind-libs-32bit~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-32bit", rpm: "bind-libs-debuginfo-32bit~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ind-doc", rpm: "ind-doc~9.9.9P1~48.6.1", rls: "openSUSELeap42.2" ) )){
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

