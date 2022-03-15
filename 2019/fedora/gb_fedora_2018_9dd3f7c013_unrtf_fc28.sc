if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875412" );
	script_version( "2021-09-02T08:01:23+0000" );
	script_cve_id( "CVE-2016-10091" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 08:01:23 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-25 21:03:00 +0000 (Tue, 25 Apr 2017)" );
	script_tag( name: "creation_date", value: "2019-01-16 04:05:07 +0100 (Wed, 16 Jan 2019)" );
	script_name( "Fedora Update for unrtf FEDORA-2018-9dd3f7c013" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-9dd3f7c013" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7D26XARRMMRMOV4KV6M2BTJ6G4G54QJV" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'unrtf' package(s) announced via the FEDORA-2018-9dd3f7c013 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "affected", value: "unrtf on Fedora 28." );
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
	if(( res = isrpmvuln( pkg: "unrtf", rpm: "unrtf~0.21.9~8.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

