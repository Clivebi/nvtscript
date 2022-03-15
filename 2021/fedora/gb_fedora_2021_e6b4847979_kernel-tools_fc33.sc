if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879482" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-23133", "CVE-2021-29155" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-23 02:15:00 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-27 03:07:30 +0000 (Tue, 27 Apr 2021)" );
	script_name( "Fedora: Security Advisory for kernel-tools (FEDORA-2021-e6b4847979)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-e6b4847979" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3ZAT2BTLTBWG76JQQEWETLQN4KVW2VEL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-tools'
  package(s) announced via the FEDORA-2021-e6b4847979 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the tools/ directory from the kernel source
and the supporting documentation." );
	script_tag( name: "affected", value: "'kernel-tools' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~5.11.16~200.fc33", rls: "FC33" ) )){
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

