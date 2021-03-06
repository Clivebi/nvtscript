if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0884.1" );
	script_cve_id( "CVE-2015-3228" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-21 01:29:00 +0000 (Thu, 21 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0884-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0884-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160884-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript' package(s) announced via the SUSE-SU-2016:0884-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ghostscript was updated to fix one security issue and one bug.
The following vulnerability was fixed:
* CVE-2015-3228: Specially crafted ps files could have caused an out of
 bound read/write due to an integer overflow, causing a segfault in the
 application or having unspecified further impact.
Also a non security bug was fixed:
- fix a crash in mutex handling (bsc#963017)" );
	script_tag( name: "affected", value: "'ghostscript' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.15~6.5", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debuginfo", rpm: "ghostscript-debuginfo~9.15~6.5", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debugsource", rpm: "ghostscript-debugsource~9.15~6.5", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11", rpm: "ghostscript-x11~9.15~6.5", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11-debuginfo", rpm: "ghostscript-x11-debuginfo~9.15~6.5", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.15~6.5", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debuginfo", rpm: "ghostscript-debuginfo~9.15~6.5", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-debugsource", rpm: "ghostscript-debugsource~9.15~6.5", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11", rpm: "ghostscript-x11~9.15~6.5", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11-debuginfo", rpm: "ghostscript-x11-debuginfo~9.15~6.5", rls: "SLES12.0SP1" ) )){
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

