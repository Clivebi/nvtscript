if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1409.1" );
	script_cve_id( "CVE-2019-13117", "CVE-2019-13118", "CVE-2019-18197" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:02 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1409-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1409-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201409-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxslt' package(s) announced via the SUSE-SU-2020:1409-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libxslt fixes the following issues:

Security issues fixed:

CVE-2019-13118: Fixed a read of uninitialized stack data (bsc#1140101).

CVE-2019-13117: Fixed a uninitialized read which allowed to discern
 whether a byte on the stack contains certain special characters
 (bsc#1140095).

CVE-2019-18197: Fixed a dangling pointer in xsltCopyText which may have
 led to information disclosure (bsc#1154609)." );
	script_tag( name: "affected", value: "'libxslt' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libxslt-debugsource", rpm: "libxslt-debugsource~1.1.32~3.8.24", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxslt-devel", rpm: "libxslt-devel~1.1.32~3.8.24", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxslt-tools", rpm: "libxslt-tools~1.1.32~3.8.24", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxslt-tools-debuginfo", rpm: "libxslt-tools-debuginfo~1.1.32~3.8.24", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxslt1", rpm: "libxslt1~1.1.32~3.8.24", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxslt1-debuginfo", rpm: "libxslt1-debuginfo~1.1.32~3.8.24", rls: "SLES15.0SP1" ) )){
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

