if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875332" );
	script_version( "2021-06-08T02:00:22+0000" );
	script_cve_id( "CVE-2018-14651", "CVE-2018-14652", "CVE-2018-14653", "CVE-2018-14654", "CVE-2018-14659", "CVE-2018-14660", "CVE-2018-14661" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-08 02:00:22 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-02 07:29:00 +0000 (Tue, 02 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-12-04 08:34:16 +0100 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for glusterfs FEDORA-2018-af9bd28cf1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-af9bd28cf1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TJ2XGXMVROM73JR6TECDQGU7MDSX72PP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glusterfs'
  package(s) announced via the FEDORA-2018-af9bd28cf1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "glusterfs on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "glusterfs", rpm: "glusterfs~4.1.6~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

