if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/097311.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.865232" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-01-24 09:25:01 +0530 (Thu, 24 Jan 2013)" );
	script_cve_id( "CVE-2013-0155", "CVE-2013-0156", "CVE-2012-6496", "CVE-2012-2695", "CVE-2012-2661" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "FEDORA", value: "2013-0635" );
	script_name( "Fedora Update for rubygem-activerecord FEDORA-2013-0635" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-activerecord'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC17" );
	script_tag( name: "affected", value: "rubygem-activerecord on Fedora 17" );
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
	if(( res = isrpmvuln( pkg: "rubygem-activerecord", rpm: "rubygem-activerecord~3.0.11~5.fc17", rls: "FC17" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

