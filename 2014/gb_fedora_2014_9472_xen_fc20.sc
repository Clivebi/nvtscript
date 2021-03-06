if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868122" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-24 06:04:43 +0200 (Sun, 24 Aug 2014)" );
	script_cve_id( "CVE-2014-5146", "CVE-2014-4021", "CVE-2014-3967", "CVE-2014-3968", "CVE-2014-3124", "CVE-2014-2599", "CVE-2013-2212", "CVE-2014-1950", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894", "CVE-2014-1895", "CVE-2014-1896", "CVE-2014-1666", "CVE-2014-1642", "CVE-2013-6400", "CVE-2013-6885", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6375", "CVE-2014-5149" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Fedora Update for xen FEDORA-2014-9472" );
	script_tag( name: "affected", value: "xen on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-9472" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-August/136980.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~4.3.2~7.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

