if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878233" );
	script_version( "2021-07-13T11:00:50+0000" );
	script_cve_id( "CVE-2020-16845" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 11:00:50 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:52:25 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Fedora: Security Advisory for golang-github-ulikunitz-xz (FEDORA-2020-deff052e7a)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-deff052e7a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KWRBAH4UZJO3RROQ72SYCUPFCJFA22FO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-github-ulikunitz-xz'
  package(s) announced via the FEDORA-2020-deff052e7a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This Go language package supports the reading and writing of xz compressed
streams. It includes also a gxz command for compressing and decompressing data.
The package is completely written in Go and doesn&#39, t have any dependency on any C
code." );
	script_tag( name: "affected", value: "'golang-github-ulikunitz-xz' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "golang-github-ulikunitz-xz", rpm: "golang-github-ulikunitz-xz~0.5.8~1.fc31", rls: "FC31" ) )){
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

