if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874035" );
	script_version( "2021-06-10T11:00:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-10 11:00:22 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-19 07:45:36 +0100 (Fri, 19 Jan 2018)" );
	script_cve_id( "CVE-2017-5753", "CVE-2017-5715" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for webkitgtk4 FEDORA-2018-690989736a" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkitgtk4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "webkitgtk4 on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-690989736a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QBIXN2ASCJJFWASPNTYVCOKF6D6LQPDL" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "webkitgtk4", rpm: "webkitgtk4~2.18.5~1.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
