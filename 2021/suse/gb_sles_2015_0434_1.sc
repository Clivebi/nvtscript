if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0434.1" );
	script_cve_id( "CVE-2014-9447" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2015-04-18 01:59:00 +0000 (Sat, 18 Apr 2015)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0434-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0434-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150434-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'elfutils' package(s) announced via the SUSE-SU-2015:0434-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "elfutils has been updated to fix one security issue:

 * CVE-2014-9447: Directory traversal vulnerability in the
 read_long_names function in libelf/elf_begin.c in elfutils 0.152 and
 0.161 allowed remote attackers to write to arbitrary files to the
 root directory via a / (slash) in a crafted archive, as demonstrated
 using the ar program (bnc#911662).

Security Issues:

 * CVE-2014-9447" );
	script_tag( name: "affected", value: "'elfutils' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "elfutils", rpm: "elfutils~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasm1", rpm: "libasm1~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libasm1-32bit", rpm: "libasm1-32bit~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdw1", rpm: "libdw1~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdw1-32bit", rpm: "libdw1-32bit~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdw1-x86", rpm: "libdw1-x86~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libebl1", rpm: "libebl1~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libebl1-32bit", rpm: "libebl1-32bit~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libebl1-x86", rpm: "libebl1-x86~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libelf1", rpm: "libelf1~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libelf1-32bit", rpm: "libelf1-32bit~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libelf1-x86", rpm: "libelf1-x86~0.152~4.9.17", rls: "SLES11.0SP3" ) )){
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

