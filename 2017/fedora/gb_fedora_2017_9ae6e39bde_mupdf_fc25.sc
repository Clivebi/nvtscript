if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873897" );
	script_version( "2021-09-13T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 10:01:53 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-11 08:04:47 +0100 (Mon, 11 Dec 2017)" );
	script_cve_id( "CVE-2017-15369", "CVE-2017-15587", "CVE-2017-9216", "CVE-2017-14685", "CVE-2017-14686", "CVE-2017-14687" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-07 13:20:00 +0000 (Tue, 07 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for mupdf FEDORA-2017-9ae6e39bde" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mupdf'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "mupdf on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-9ae6e39bde" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P5HUMQDKNC7MAYB5VDA6XA5BVYTZFZQY" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC25" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC25"){
	if(( res = isrpmvuln( pkg: "mupdf", rpm: "mupdf~1.11~9.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
