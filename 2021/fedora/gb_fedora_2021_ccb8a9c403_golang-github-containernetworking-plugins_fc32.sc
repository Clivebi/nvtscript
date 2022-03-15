if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878785" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2020-10749" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 13:57:00 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 10:59:06 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Fedora: Security Advisory for golang-github-containernetworking-plugins (FEDORA-2021-ccb8a9c403)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2021-ccb8a9c403" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DV3HCDZYUTPPVDUMTZXDKK6IUO3JMGJC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-github-containernetworking-plugins'
  package(s) announced via the FEDORA-2021-ccb8a9c403 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Some CNI network plugins, maintained by the containernetworking team." );
	script_tag( name: "affected", value: "'golang-github-containernetworking-plugins' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "golang-github-containernetworking-plugins", rpm: "golang-github-containernetworking-plugins~0.9.0~1.fc32", rls: "FC32" ) )){
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

