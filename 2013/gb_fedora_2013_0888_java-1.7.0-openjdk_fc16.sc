if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/096995.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.865053" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-01-21 09:26:58 +0530 (Mon, 21 Jan 2013)" );
	script_cve_id( "CVE-2012-4681", "CVE-2012-0497", "CVE-2011-3571", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0502", "CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0501", "CVE-2012-0506", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3544", "CVE-2011-3521", "CVE-2011-3554", "CVE-2011-3389", "CVE-2011-3558", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560", "CVE-2013-0422", "CVE-2012-3174" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2013-0888" );
	script_name( "Fedora Update for java-1.7.0-openjdk FEDORA-2013-0888" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.7.0-openjdk'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	script_tag( name: "affected", value: "java-1.7.0-openjdk on Fedora 16" );
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
if(release == "FC16"){
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.9~2.3.4.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
