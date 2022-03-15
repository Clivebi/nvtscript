if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873282" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-16 07:50:16 +0200 (Wed, 16 Aug 2017)" );
	script_cve_id( "CVE-2017-12067", "CVE-2016-8685", "CVE-2016-8686", "CVE-2016-8694", "CVE-2016-8695", "CVE-2016-8696", "CVE-2016-8697", "CVE-2016-8698", "CVE-2016-8699", "CVE-2016-8700", "CVE-2016-8701", "CVE-2016-8702", "CVE-2016-8703", "CVE-2017-7263" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-02-05 20:16:00 +0000 (Sun, 05 Feb 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for potrace FEDORA-2017-d7739ff31b" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'potrace'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "potrace on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-d7739ff31b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H2HN4FM6SARZE3UNQLLA5HCBOE4ZJV63" );
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
	if(( res = isrpmvuln( pkg: "potrace", rpm: "potrace~1.15~1.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

