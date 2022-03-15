if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873555" );
	script_version( "2021-09-13T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 10:01:53 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-02 18:05:39 +0530 (Thu, 02 Nov 2017)" );
	script_cve_id( "CVE-2017-15096" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-14 18:45:00 +0000 (Tue, 14 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for glusterfs FEDORA-2017-a47c76eeb1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glusterfs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "glusterfs on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-a47c76eeb1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ULF6MJXQTFLIZTS5F7MWFE2GUXJYR4FN" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC26" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC26"){
	if(( res = isrpmvuln( pkg: "glusterfs", rpm: "glusterfs~3.10.6~4.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

