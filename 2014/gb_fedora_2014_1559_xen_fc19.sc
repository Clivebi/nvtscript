if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867263" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-03 13:29:35 +0530 (Mon, 03 Feb 2014)" );
	script_cve_id( "CVE-2014-1666", "CVE-2014-1642", "CVE-2013-6400", "CVE-2013-6885", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6375", "CVE-2013-4551", "CVE-2013-4494", "CVE-2013-4416", "CVE-2013-4368", "CVE-2013-4369", "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-1442", "CVE-2013-4329", "CVE-2013-1918", "CVE-2013-1432", "CVE-2013-2211", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Fedora Update for xen FEDORA-2014-1559" );
	script_tag( name: "affected", value: "xen on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-1559" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-February/127580.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC19" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC19"){
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~4.2.3~14.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

