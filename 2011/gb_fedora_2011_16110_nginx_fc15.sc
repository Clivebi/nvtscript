if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-December/070586.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.863654" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-12-09 10:50:29 +0530 (Fri, 09 Dec 2011)" );
	script_xref( name: "FEDORA", value: "2011-16110" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-4315" );
	script_name( "Fedora Update for nginx FEDORA-2011-16110" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nginx'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC15" );
	script_tag( name: "affected", value: "nginx on Fedora 15" );
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
if(release == "FC15"){
	if(( res = isrpmvuln( pkg: "nginx", rpm: "nginx~1.0.10~1.fc15", rls: "FC15" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

