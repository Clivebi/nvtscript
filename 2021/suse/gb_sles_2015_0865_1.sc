if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0865.1" );
	script_cve_id( "CVE-2015-1798", "CVE-2015-1799", "CVE-2015-3405" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-28 14:08:00 +0000 (Thu, 28 May 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0865-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0865-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150865-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2015:0865-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ntp was updated to fix two security related flaws as well as 'slew' mode handling for leap seconds.
The following vulnerabilities were fixed:
* ntpd could accept unauthenticated packets with symmetric key crypto.
 (CVE-2015-1798)
* ntpd authentication did not protect symmetric associations against DoS
 attacks (CVE-2015-1799)
* ntp-keygen may generate non-random symmetric keys on big-endian systems
 (bsc#928321, CVE-2015-3405).
The following non-security issues were fixed:
* Fix slew mode for leap seconds (bnc#918342)." );
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
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~44.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debuginfo", rpm: "ntp-debuginfo~4.2.6p5~44.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debugsource", rpm: "ntp-debugsource~4.2.6p5~44.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.6p5~44.1", rls: "SLES12.0" ) )){
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

