if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879588" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2021-31829" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-23 02:15:00 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-13 03:33:19 +0000 (Thu, 13 May 2021)" );
	script_name( "Fedora: Security Advisory for kernel-tools (FEDORA-2021-9c0276e935)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-9c0276e935" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PD4LLHGNH3VFBWRWTJI3WOD2NXKIVL6D" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-tools'
  package(s) announced via the FEDORA-2021-9c0276e935 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the tools/ directory from the kernel source
and the supporting documentation." );
	script_tag( name: "affected", value: "'kernel-tools' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~5.11.19~100.fc32", rls: "FC32" ) )){
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

