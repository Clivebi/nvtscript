if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3348.1" );
	script_cve_id( "CVE-2018-12207", "CVE-2019-11135" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3348-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3348-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193348-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spectre-meltdown-checker' package(s) announced via the SUSE-SU-2019:3348-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spectre-meltdown-checker fixes the following issues:

 - feat: implement TAA detection (CVE-2019-11135 bsc#1139073)
 - feat: implement MCEPSC / iTLB Multihit detection (CVE-2018-12207
 bsc#1117665)
 - feat: taa: add TSX_CTRL MSR detection in hardware info
 - feat: fwdb: use both Intel GitHub repo and MCEdb to build our firmware
 version database
 - feat: use --live with --kernel/--config/--map to override file
 detection in live mode
 - enh: rework the vuln logic of MDS with --paranoid (fixes #307)
 - enh: explain that Enhanced IBRS is better for performance than classic
 IBRS
 - enh: kernel: autodetect customized arch kernels from cmdline
 - enh: kernel decompression: better tolerance against missing tools
 - enh: mock: implement reading from /proc/cmdline
 - fix: variant3a: Silvermont CPUs are not vulnerable to variant 3a
 - fix: lockdown: detect Red Hat locked down kernels (impacts MSR writes)
 - fix: lockdown: detect locked down mode in vanilla 5.4+ kernels
 - fix: sgx: on locked down kernels, fallback to CPUID bit for detection
 - fix: fwdb: builtin version takes precedence if the local cached
 version is older
 - fix: pteinv: don't check kernel image if not available
 - fix: silence useless error from grep (fixes #322)
 - fix: msr: fix msr module detection under Ubuntu 19.10 (fixes #316)
 - fix: mocking value for read_msr
 - chore: rename mcedb cmdline parameters to fwdb, and change db version
 scheme
 - chore: fwdb: update to v130.20191104+i20191027
 - chore: add GitHub check workflow" );
	script_tag( name: "affected", value: "'spectre-meltdown-checker' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "spectre-meltdown-checker", rpm: "spectre-meltdown-checker~0.43~3.3.1", rls: "SLES15.0SP1" ) )){
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

