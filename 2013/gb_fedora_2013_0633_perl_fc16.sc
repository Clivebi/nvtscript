if(description){
	script_tag( name: "affected", value: "perl on Fedora 16" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/097440.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.865242" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-01-28 09:33:33 +0530 (Mon, 28 Jan 2013)" );
	script_cve_id( "CVE-2012-6329", "CVE-2011-2728" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-0633" );
	script_name( "Fedora Update for perl FEDORA-2013-0633" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC16"){
	if(( res = isrpmvuln( pkg: "perl", rpm: "perl~5.14.3~205.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

