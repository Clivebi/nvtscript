if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851674" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-05 23:56:28 +0100 (Fri, 05 Jan 2018)" );
	script_cve_id( "CVE-2017-5715" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for kernel-firmware (openSUSE-SU-2018:0026-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-firmware'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kernel-firmware fixes the following issues:

  - Add microcode_amd_fam17h.bin (bsc#1068032 CVE-2017-5715)

  This new firmware disables branch prediction on AMD family 17h processor
  to mitigate an attack on the branch predictor that could lead to
  information disclosure from e.g. kernel memory (bsc#1068032 CVE-2017-5715).

  This update was imported from the SUSE:SLE-12-SP2:Update update project." );
	script_tag( name: "affected", value: "kernel-firmware on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:0026-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-01/msg00018.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~20170530~7.12.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ucode-amd", rpm: "ucode-amd~20170530~7.12.1", rls: "openSUSELeap42.2" ) )){
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

