if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.865627" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-23 09:53:11 +0530 (Thu, 23 May 2013)" );
	script_cve_id( "CVE-2013-2059", "CVE-2013-2030", "CVE-2013-2006", "CVE-2013-1865", "CVE-2013-0282", "CVE-2013-1664", "CVE-2013-1665", "CVE-2013-0247" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for openstack-keystone FEDORA-2013-8048" );
	script_xref( name: "FEDORA", value: "2013-8048" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-May/105916.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openstack-keystone'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	script_tag( name: "affected", value: "openstack-keystone on Fedora 18" );
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
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "openstack-keystone", rpm: "openstack-keystone~2012.2.4~3.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

