if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3787.1" );
	script_cve_id( "CVE-2018-18386", "CVE-2018-5391" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-21 16:00:00 +0000 (Thu, 21 Mar 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3787-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3787-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183787-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 17 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2018:3787-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.4.103-92_56 fixes several issues.

The following security issues were fixed:
CVE-2018-5391: Fixed a denial of service attack with low rates of
 specially modified packets targeting IP fragment re-assembly. An
 attacker may have caused a denial of service condition by sending
 specially crafted IP fragments. The current vulnerability
 (CVE-2018-5391) became exploitable in the Linux kernel with the increase
 of the IP fragment reassembly queue size (bsc#1103098).

CVE-2018-18386: The drivers/tty/n_tty.c allowed local attackers (who are
 able to access pseudo terminals) to hang/block further usage of any
 pseudo terminal devices due to an EXTPROC versus ICANON confusion in
 TIOCINQ (bsc#1112039)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 17 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_103-92_53-default", rpm: "kgraft-patch-4_4_103-92_53-default~11~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_103-92_56-default", rpm: "kgraft-patch-4_4_103-92_56-default~11~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_90-92_50-default", rpm: "kgraft-patch-4_4_90-92_50-default~12~2.1", rls: "SLES12.0SP2" ) )){
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

