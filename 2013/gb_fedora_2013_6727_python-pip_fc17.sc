if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.865599" );
	script_version( "2021-03-18T08:58:31+0000" );
	script_tag( name: "last_modification", value: "2021-03-18 08:58:31 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "creation_date", value: "2013-05-06 13:51:14 +0530 (Mon, 06 May 2013)" );
	script_cve_id( "CVE-2013-1888" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Fedora Update for python-pip FEDORA-2013-6727" );
	script_xref( name: "FEDORA", value: "2013-6727" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-May/104603.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pip'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC17" );
	script_tag( name: "affected", value: "python-pip on Fedora 17" );
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
	if(( res = isrpmvuln( pkg: "python-pip", rpm: "python-pip~1.3.1~1.fc17", rls: "FC17" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

