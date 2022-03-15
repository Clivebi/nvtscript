if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872176" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-23 06:06:59 +0100 (Fri, 23 Dec 2016)" );
	script_cve_id( "CVE-2016-8652" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-02-22 19:11:00 +0000 (Wed, 22 Feb 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for dovecot FEDORA-2016-bb22a24d3d" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "dovecot on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-bb22a24d3d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P3YBFOJU7UF6GOOMMMQLKEB42EGP7LQW" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "dovecot", rpm: "dovecot~2.2.27~1.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
