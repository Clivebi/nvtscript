if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879288" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2020-27840", "CVE-2021-20277" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 19:46:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-03-27 04:05:33 +0000 (Sat, 27 Mar 2021)" );
	script_name( "Fedora: Security Advisory for libldb (FEDORA-2021-c2d8628d33)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-c2d8628d33" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WZA3EWGR5D6C3ZXC4F5RWFTGW2T5N7XX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libldb'
  package(s) announced via the FEDORA-2021-c2d8628d33 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An extensible library that implements an LDAP like API to access remote LDAP
servers, or use local tdb databases." );
	script_tag( name: "affected", value: "'libldb' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "libldb", rpm: "libldb~2.3.0~1.fc34", rls: "FC34" ) )){
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

