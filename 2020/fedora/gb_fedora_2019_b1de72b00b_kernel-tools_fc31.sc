if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877161" );
	script_version( "2021-07-19T11:00:51+0000" );
	script_cve_id( "CVE-2019-17056", "CVE-2019-17055", "CVE-2019-17054", "CVE-2019-17053", "CVE-2019-17052" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-25 20:15:00 +0000 (Fri, 25 Oct 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:29:04 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for kernel-tools FEDORA-2019-b1de72b00b" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-b1de72b00b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ILQ4RUZFRR65OIVJELZHCQ4GASLR4CAM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-tools'
  package(s) announced via the FEDORA-2019-b1de72b00b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the tools/ directory from the kernel source
and the supporting documentation." );
	script_tag( name: "affected", value: "'kernel-tools' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~5.3.4~300.fc31", rls: "FC31" ) )){
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

