if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1313.1" );
	script_cve_id( "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 16:29:00 +0000 (Tue, 11 Jun 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1313-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1313-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191313-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2019:1313-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ucode-intel fixes the following issues:

The Intel CPU Microcode was updated to the official QSR 2019.1 Microcode release (bsc#1111331 CVE-2018-12126 CVE-2018-12130 CVE-2018-12127 CVE-2019-11091)

---- new platforms ---------------------------------------- VLV
 C0 6-37-8/02 00000838 Atom Z series VLV C0
 6-37-8/0C 00000838 Celeron N2xxx, Pentium N35xx VLV
 D0 6-37-9/0F 0000090c Atom E38xx CHV C0
 6-4c-3/01 00000368 Atom X series CHV D0
 6-4c-4/01 00000411 Atom X series

Readded missing in last update:

BDX-ML B0/M0/R0 6-4f-1/ef 0b00002e->00000036 Xeon E5/E7 v4, Core i7-69xx/68xx" );
	script_tag( name: "affected", value: "'ucode-intel' package(s) on SUSE Linux Enterprise Module for Basesystem 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "ucode-intel", rpm: "ucode-intel~20190514~3.19.1", rls: "SLES15.0" ) )){
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

