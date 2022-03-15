if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875560" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-9857", "CVE-2019-3882" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-09 02:09:01 +0000 (Tue, 09 Apr 2019)" );
	script_name( "Fedora Update for kernel-headers FEDORA-2019-65c6d11eba" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-65c6d11eba" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FAK7AKF6QBGKN6S2KHUOS7GZZLOVKKP2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'kernel-headers' package(s) announced via the FEDORA-2019-65c6d11eba advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Kernel-headers includes the C header files
  that specify the interface between the Linux kernel and userspace libraries
  and programs.  The header files define structures and constants that are needed
  for building most standard programs and are also needed for rebuilding the glibc
  package." );
	script_tag( name: "affected", value: "'kernel-headers' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~5.0.6~100.fc28", rls: "FC28" ) )){
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

