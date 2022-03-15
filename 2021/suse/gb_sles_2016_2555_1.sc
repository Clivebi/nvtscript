if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2555.1" );
	script_cve_id( "CVE-2015-8325", "CVE-2016-1908", "CVE-2016-3115", "CVE-2016-6210", "CVE-2016-6515" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2555-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2555-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162555-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh-openssl1' package(s) announced via the SUSE-SU-2016:2555-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssh-openssl1 fixes the following issues:
Security issues fixed:
- CVE-2016-6210: Prevent user enumeration through the timing of password
 processing (bsc#989363)
- CVE-2016-6515: limit accepted password length (prevents possible DoS)
 (bsc#992533)
- CVE-2016-3115: Sanitise input for xauth(1) (bsc#970632)
- CVE-2016-1908: prevent X11 SECURITY circumvention when forwarding X11
 connections (bsc#962313)
- CVE-2015-8325: ignore PAM environment when using login (bsc#975865)
- Disable DH parameters under 2048 bits by default and allow lowering the
 limit back to the RFC 4419 specified minimum through an option
 (bsc#932483, bsc#948902)
- Allow lowering the DH groups parameter limit in server as well as when
 GSSAPI key exchange is used (bsc#948902)
Bugs fixed:
- avoid complaining about unset DISPLAY variable (bsc#981654)
- Correctly parse GSSAPI KEX algorithms (bsc#961368)
- more verbose FIPS mode/CC related documentation in README.FIPS
 (bsc#965576, bsc#960414)
- fix PRNG re-seeding (bsc#960414, bsc#729190)
- Allow empty Match blocks (bsc#961494)" );
	script_tag( name: "affected", value: "'openssh-openssl1' package(s) on SUSE Linux Enterprise Server 11." );
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
if(release == "SLES11.0"){
	if(!isnull( res = isrpmvuln( pkg: "openssh-openssl1", rpm: "openssh-openssl1~6.6p1~15.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-openssl1-helpers", rpm: "openssh-openssl1-helpers~6.6p1~15.1", rls: "SLES11.0" ) )){
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

