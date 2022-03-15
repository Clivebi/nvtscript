if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.865577" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-04-22 10:29:45 +0530 (Mon, 22 Apr 2013)" );
	script_cve_id( "CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1537", "CVE-2013-2415", "CVE-2013-2423", "CVE-2013-2424", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2436", "CVE-2013-2420", "CVE-2013-1558", "CVE-2013-2422", "CVE-2013-2431", "CVE-2013-1518", "CVE-2013-1557", "CVE-2013-2421", "CVE-2013-2426", "CVE-2013-2419", "CVE-2013-2417", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-1569", "CVE-2012-4681" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Fedora Update for java-1.7.0-openjdk FEDORA-2013-5922" );
	script_xref( name: "FEDORA", value: "2013-5922" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/102111.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.7.0-openjdk'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC17" );
	script_tag( name: "affected", value: "java-1.7.0-openjdk on Fedora 17" );
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
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.19~2.3.9.1.fc17", rls: "FC17" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

