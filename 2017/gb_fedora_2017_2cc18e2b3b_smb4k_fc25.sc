if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872694" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-21 07:16:39 +0200 (Sun, 21 May 2017)" );
	script_cve_id( "CVE-2017-8849" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-18 16:41:00 +0000 (Mon, 18 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for smb4k FEDORA-2017-2cc18e2b3b" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'smb4k'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "smb4k on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-2cc18e2b3b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KRE6NA5IJ7WI4PPZTYCLCQQSXGHSSU2B" );
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
	if(( res = isrpmvuln( pkg: "smb4k", rpm: "smb4k~1.2.2~3.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

