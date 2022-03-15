if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1571.1" );
	script_cve_id( "CVE-2013-2020", "CVE-2013-2021", "CVE-2013-6497", "CVE-2014-9050" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:15 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2015-09-28 16:31:00 +0000 (Mon, 28 Sep 2015)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1571-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1571-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141571-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2014:1571-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "clamav was updated to version 0.98.5 to fix five security issues:

 * Crash when scanning maliciously crafted yoda's crypter files
 (CVE-2013-6497).
 * Heap-based buffer overflow when scanning crypted PE files
 (CVE-2014-9050).
 * Fix heap corruption (CVE-2013-2020).
 * Fix overflow due to PDF key length computation (CVE-2013-2021).
 * Crash when using 'clamscan -a'.

Several non-security issues have also been fixed, please refer to the package's change log for details.

Security Issues:

 * CVE-2013-6497
 * CVE-2014-9050
 * CVE-2013-2021
 * CVE-2013-2020" );
	script_tag( name: "affected", value: "'clamav' package(s) on SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.98.5~0.5.1", rls: "SLES11.0SP1" ) )){
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.98.5~0.5.1", rls: "SLES11.0SP2" ) )){
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

