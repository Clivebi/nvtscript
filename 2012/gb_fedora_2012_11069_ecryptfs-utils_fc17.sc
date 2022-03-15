if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-August/084605.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864598" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-08-30 11:22:32 +0530 (Thu, 30 Aug 2012)" );
	script_cve_id( "CVE-2012-3409" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-03 15:36:00 +0000 (Fri, 03 Jan 2020)" );
	script_xref( name: "FEDORA", value: "2012-11069" );
	script_name( "Fedora Update for ecryptfs-utils FEDORA-2012-11069" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ecryptfs-utils'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC17" );
	script_tag( name: "affected", value: "ecryptfs-utils on Fedora 17" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC17"){
	if(( res = isrpmvuln( pkg: "ecryptfs-utils", rpm: "ecryptfs-utils~99~1.fc17", rls: "FC17" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

