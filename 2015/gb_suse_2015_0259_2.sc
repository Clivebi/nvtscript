if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851113" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 20:17:02 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9297", "CVE-2014-9298" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for ntp (SUSE-SU-2015:0259-2)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ntp has been updated to fix four security issues:

  * CVE-2014-9294: ntp-keygen used a weak RNG seed, which made it easier
  for remote attackers to defeat cryptographic protection mechanisms
  via a brute-force attack. (bsc#910764)

  * CVE-2014-9293: The config_auth function, when an auth key is not
  configured, improperly generated a key, which made it easier for
  remote attackers to defeat cryptographic protection mechanisms via a
  brute-force attack. (bsc#910764)

  * CVE-2014-9298: ::1 can be spoofed on some operating systems, so ACLs
  based on IPv6 ::1 addresses could be bypassed. (bsc#910764)

  * CVE-2014-9297: vallen is not validated in several places in
  ntp_crypto.c, leading to potential information leak. (bsc#910764)

  Security Issues:

  * CVE-2014-9294

  * CVE-2014-9293

  * CVE-2014-9298

  * CVE-2014-9297" );
	script_tag( name: "affected", value: "ntp on SUSE Linux Enterprise Server 11 SP2 LTSS" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0259-2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP2" );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.4p8~1.29.32.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.4p8~1.29.32.1", rls: "SLES11.0SP2" ) )){
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

