if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868796" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-05 14:52:20 +0100 (Mon, 05 Jan 2015)" );
	script_cve_id( "CVE-2014-9280", "CVE-2014-9279", "CVE-2014-6316", "CVE-2014-9117", "CVE-2014-9089", "CVE-2014-7146", "CVE-2014-8598", "CVE-2014-8554", "CVE-2014-9272", "CVE-2014-9281", "CVE-2014-9270", "CVE-2014-9269", "CVE-2014-8987", "CVE-2014-8988", "CVE-2014-8986" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for mantis FEDORA-2014-16609" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mantis'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "mantis on Fedora 21" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2014-16609" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146599.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC21" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC21"){
	if(( res = isrpmvuln( pkg: "mantis", rpm: "mantis~1.2.18~1.fc21", rls: "FC21" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

