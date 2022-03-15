if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.2215.1" );
	script_cve_id( "CVE-2014-9732", "CVE-2015-4467", "CVE-2015-4469", "CVE-2015-4470", "CVE-2015-4471", "CVE-2015-4472" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-22 02:59:00 +0000 (Thu, 22 Dec 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:2215-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:2215-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20152215-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmspack' package(s) announced via the SUSE-SU-2015:2215-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libmspack was updated to fix several security vulnerabilities.
- Fix null pointer dereference on a crafted CAB. (bsc#934524,
 CVE-2014-9732)
- Fix denial of service while processing crafted CHM file. (bsc#934525,
 CVE-2015-4467)
- Fix denial of service while processing crafted CHM file. (bsc#934529,
 CVE-2015-4472)
- Fix pointer arithmetic overflow during CHM decompression. (bsc#934526,
 CVE-2015-4469)
- Fix off-by-one buffer over-read in mspack/mszipd.c. (bsc#934527,
 CVE-2015-4470)
- Fix off-by-one buffer under-read in mspack/lzxd.c. (bsc#934528,
 CVE-2015-4471)" );
	script_tag( name: "affected", value: "'libmspack' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for VMWare 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libmspack0", rpm: "libmspack0~0.0.20060920alpha~74.10.1", rls: "SLES11.0SP3" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libmspack0", rpm: "libmspack0~0.0.20060920alpha~74.10.1", rls: "SLES11.0SP4" ) )){
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

