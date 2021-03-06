if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-June/082375.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864457" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-19 09:36:04 +0530 (Tue, 19 Jun 2012)" );
	script_cve_id( "CVE-2012-1711", "CVE-2012-1717", "CVE-2012-1716", "CVE-2012-1713", "CVE-2012-1719", "CVE-2012-1718", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3544", "CVE-2011-3521", "CVE-2011-3554", "CVE-2011-3389", "CVE-2011-3558", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560", "CVE-2011-0872", "CVE-2011-0865", "CVE-2011-0815", "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0867", "CVE-2011-0869", "CVE-2011-0870", "CVE-2011-0868", "CVE-2011-0871", "CVE-2011-0864" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2012-9541" );
	script_name( "Fedora Update for java-1.6.0-openjdk FEDORA-2012-9541" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC15" );
	script_tag( name: "affected", value: "java-1.6.0-openjdk on Fedora 15" );
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
if(release == "FC15"){
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.0~65.1.10.8.fc15", rls: "FC15" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

