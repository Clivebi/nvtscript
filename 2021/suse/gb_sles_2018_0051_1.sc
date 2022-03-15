if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0051.1" );
	script_cve_id( "CVE-2017-5715" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0051-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0051-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180051-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2018:0051-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kernel-firmware fixes the following issues:
- Add microcode_amd_fam17h.bin (bsc#1068032 CVE-2017-5715)
This new firmware enables the Indirect Branch Control (IBC) feature on AMD family 17h processor to mitigate an attack on the branch predictor that could lead to information disclosure from e.g. kernel memory (bsc#1068032 CVE-2017-5715)." );
	script_tag( name: "affected", value: "'kernel-firmware' package(s) on SUSE Linux Enterprise Server 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~20140807git~5.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ucode-amd", rpm: "ucode-amd~20140807git~5.3.1", rls: "SLES12.0" ) )){
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

