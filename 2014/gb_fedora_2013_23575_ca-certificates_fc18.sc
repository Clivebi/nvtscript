if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867213" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-03 12:30:27 +0530 (Fri, 03 Jan 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for ca-certificates FEDORA-2013-23575" );
	script_tag( name: "affected", value: "ca-certificates on Fedora 18" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-23575" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-December/125373.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ca-certificates'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "ca-certificates", rpm: "ca-certificates~2013.1.95~1.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
