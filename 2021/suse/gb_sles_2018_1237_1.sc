if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1237.1" );
	script_cve_id( "CVE-2017-0861", "CVE-2018-1000199" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1237-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1237-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181237-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 23 for SLE 12 SP1)' package(s) announced via the SUSE-SU-2018:1237-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 3.12.74-60_64_66 fixes several issues.
The following security issues were fixed:
- CVE-2018-1000199: A bug in x86 debug register handling of ptrace() could
 lead to memory corruption, possibly a denial of service or privilege
 escalation (bsc#1090036).
- CVE-2017-0861: Use-after-free vulnerability in the snd_pcm_info function
 in the ALSA subsystem in the Linux kernel allowed attackers to gain
 privileges via unspecified vectors (bsc#1088268)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 23 for SLE 12 SP1)' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_66-default", rpm: "kgraft-patch-3_12_74-60_64_66-default~4~2.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_66-xen", rpm: "kgraft-patch-3_12_74-60_64_66-xen~4~2.1", rls: "SLES12.0SP1" ) )){
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

