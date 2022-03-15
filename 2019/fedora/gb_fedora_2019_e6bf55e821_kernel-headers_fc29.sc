if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876363" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091", "CVE-2019-11884" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 16:29:00 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-05-16 02:13:42 +0000 (Thu, 16 May 2019)" );
	script_name( "Fedora Update for kernel-headers FEDORA-2019-e6bf55e821" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-e6bf55e821" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PF2PDXUGOFEOTPVEACKFIHQB6O4XUIZD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-headers'
  package(s) announced via the FEDORA-2019-e6bf55e821 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package." );
	script_tag( name: "affected", value: "'kernel-headers' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~5.0.16~200.fc29", rls: "FC29" ) )){
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
