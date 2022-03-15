if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0048.2" );
	script_cve_id( "CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-25 16:43:00 +0000 (Thu, 25 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0048-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0048-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190048-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'helm-mirror' package(s) announced via the SUSE-SU-2019:0048-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for helm-mirror to version 0.2.1 fixes the following issues:

Security issues fixed:
CVE-2018-16873: Fixed a remote command execution (bsc#1118897)

CVE-2018-16874: Fixed a directory traversal in 'go get' via curly braces
 in import path (bsc#1118898)

CVE-2018-16875: Fixed a CPU denial of service (bsc#1118899)

Non-security issue fixed:
Update to v0.2.1 (bsc#1120762)

Include helm-mirror into the containers module (bsc#1116182)" );
	script_tag( name: "affected", value: "'helm-mirror' package(s) on SUSE Linux Enterprise Module for Containers 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "helm-mirror", rpm: "helm-mirror~0.2.1~1.7.1", rls: "SLES15.0SP1" ) )){
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

