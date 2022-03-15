if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2861.1" );
	script_cve_id( "CVE-2017-5753" );
	script_tag( name: "creation_date", value: "2021-08-29 02:26:34 +0000 (Sun, 29 Aug 2021)" );
	script_version( "2021-08-29T02:26:34+0000" );
	script_tag( name: "last_modification", value: "2021-08-29 02:26:34 +0000 (Sun, 29 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 17:43:00 +0000 (Thu, 24 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2861-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2861-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212861-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spectre-meltdown-checker' package(s) announced via the SUSE-SU-2021:2861-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spectre-meltdown-checker fixes the following issues:

spectre-meltdown-checker was updated to version 0.44 (bsc#1189477)

feat: add support for SRBDS related vulnerabilities

feat: add zstd kernel decompression (#370)

enh: arm: add experimental support for binary arm images

enh: rsb filling: no longer need the 'strings' tool to check for kernel
 support in live mode

fix: fwdb: remove Intel extract tempdir on exit

fix: has_vmm: ignore kernel threads when looking for a hypervisor (fixes
 #278)

fix: fwdb: use the commit date as the intel fwdb version

fix: fwdb: update Intel's repository URL

fix: arm64: CVE-2017-5753: kernels 4.19+ use a different nospec macro

fix: on CPU parse info under FreeBSD

chore: github: add check run on pull requests

chore: fwdb: update to v165.20201021+i20200616" );
	script_tag( name: "affected", value: "'spectre-meltdown-checker' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "spectre-meltdown-checker", rpm: "spectre-meltdown-checker~0.44~3.6.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "spectre-meltdown-checker", rpm: "spectre-meltdown-checker~0.44~3.6.1", rls: "SLES15.0SP3" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "spectre-meltdown-checker", rpm: "spectre-meltdown-checker~0.44~3.6.1", rls: "SLES15.0SP1" ) )){
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

