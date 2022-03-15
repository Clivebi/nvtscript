if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0274.1" );
	script_cve_id( "CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9297", "CVE-2014-9298" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-03 02:59:00 +0000 (Tue, 03 Jan 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0274-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0274-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150274-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2015:0274-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ntp was updated to fix four security issues.

These security issues were fixed:
- CVE-2014-9294: util/ntp-keygen.c in ntp-keygen used a weak RNG seed,
 which made it easier for remote attackers to defeat cryptographic
 protection mechanisms via a brute-force attack (bnc#910764 911792).
- CVE-2014-9293: The config_auth function in ntpd, when an auth key was
 not configured, improperly generated a key, which made it easier for
 remote attackers to defeat cryptographic protection mechanisms via a
 brute-force attack (bnc#910764 911792).
- CVE-2014-9298: ::1 can be spoofed on some OSes, so ACLs based on IPv6
 ::1 addresses could be bypassed (bnc#911792).
- CVE-2014-9297: Information leak by not properly checking a length in
 several places in ntp_crypto.c (bnc#911792)." );
	script_tag( name: "affected", value: "'ntp' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~37.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debuginfo", rpm: "ntp-debuginfo~4.2.6p5~37.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debugsource", rpm: "ntp-debugsource~4.2.6p5~37.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.6p5~37.2", rls: "SLES12.0" ) )){
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

