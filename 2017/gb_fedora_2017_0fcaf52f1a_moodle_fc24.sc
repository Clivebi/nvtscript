if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872538" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-01 06:39:37 +0200 (Sat, 01 Apr 2017)" );
	script_cve_id( "CVE-2017-2641", "CVE-2017-2643", "CVE-2017-2644", "CVE-2017-2645" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for moodle FEDORA-2017-0fcaf52f1a" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "moodle on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-0fcaf52f1a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OT3KIHDUNM2GLI2CFSKIINN3YGXKZA27" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "moodle", rpm: "moodle~3.1.5~1.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
